"""Cortex lookup API primitives; credentials are loaded locally and never logged."""
from __future__ import annotations
import hashlib
import json
import re
import secrets
import string
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
MAX_RESPONSE_BYTES=50*1024*1024
LOOKUP_READ_LIMIT=10000
DATASET_READY_TIMEOUT_SECONDS=90
DATASET_READY_POLL_SECONDS=3
ENV_NAME_RE=re.compile(r"^[A-Z][A-Z0-9_]*$")


class SyncError(RuntimeError):
    """Raised when source validation or a Cortex operation is unsafe."""

@dataclass(frozen=True)
class DatasetSpec:
    name: str
    filename: str
    fields: tuple[str, ...]
    key_fields: tuple[str, ...]
    manifest_count_field: str
    manifest_hash_field: str

    @property
    def schema(self) -> dict[str, str]:
        return {field: "text" for field in self.fields}

@dataclass(frozen=True)
class Tenant:
    name: str
    api_fqdn: str
    api_key_id: str
    api_key: str = field(repr=False)
    api_key_type: str

@dataclass(frozen=True)
class Settings:
    source_base_url: str
    request_timeout_seconds: int
    mutation_interval_seconds: float
    max_delete_fraction: float

def read_limited(response: object, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    body = response.read(limit + 1)  # type: ignore[attr-defined]
    if len(body) > limit:
        raise SyncError(f"response exceeded {limit} bytes")
    return body

def validate_api_fqdn(value: str) -> str:
    candidate = value.strip().lower().rstrip("/")
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SyncError("api_fqdn must be a valid Cortex HTTPS hostname")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port:
        raise SyncError("api_fqdn must contain only the Cortex API hostname")
    return parsed.hostname

def parse_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise SyncError(f"tenant env file does not exist: {path}")
    check_secret_permissions(path)
    values: dict[str, str] = {}
    for line_number, source_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = source_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise SyncError(f"{path}:{line_number}: expected NAME=value")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not ENV_NAME_RE.fullmatch(name):
            raise SyncError(f"{path}:{line_number}: invalid environment variable name")
        if name in values:
            raise SyncError(f"{path}:{line_number}: duplicate variable {name}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[name] = value
    return values

def advanced_auth_headers(
    tenant: Tenant,
    nonce: str | None = None,
    timestamp_ms: int | None = None,
) -> dict[str, str]:
    nonce_value = nonce or "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(64)
    )
    timestamp_value = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    digest = hashlib.sha256(
        f"{tenant.api_key}{nonce_value}{timestamp_value}".encode("utf-8")
    ).hexdigest()
    return {
        "Authorization": digest,
        "x-xdr-auth-id": tenant.api_key_id,
        "x-xdr-nonce": nonce_value,
        "x-xdr-timestamp": str(timestamp_value),
    }

def unwrap_api_reply(response: object) -> object:
    if not isinstance(response, dict):
        return response
    if "reply" in response:
        return response["reply"]
    nested = response.get("response")
    if isinstance(nested, dict) and "reply" in nested:
        return nested["reply"]
    return response

class CortexClient:
    def __init__(self, tenant: Tenant, timeout: int):
        self.tenant = tenant
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.tenant.api_key_type == "advanced":
            headers.update(advanced_auth_headers(self.tenant))
        else:
            headers.update(
                {
                    "Authorization": self.tenant.api_key,
                    "x-xdr-auth-id": self.tenant.api_key_id,
                }
            )
        return headers

    def post(self, path: str, request_data: dict[str, object]) -> object:
        payload = json.dumps({"request_data": request_data}).encode("utf-8")
        request = Request(
            f"https://{self.tenant.api_fqdn}{path}",
            data=payload,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = read_limited(response)
        except HTTPError as exc:
            # Error bodies can reflect request headers. Never print an API secret.
            detail = read_limited(exc).decode("utf-8", errors="replace")
            for sensitive in (self.tenant.api_key, request.get_header('Authorization')):
                if sensitive:
                    detail = detail.replace(sensitive, '[REDACTED]')
            detail = detail[:1000]
            raise SyncError(
                f"tenant {self.tenant.name}: Cortex API {path} returned HTTP {exc.code}: {detail}"
            ) from exc
        except (URLError, TimeoutError) as exc:
            raise SyncError(
                f"tenant {self.tenant.name}: Cortex API {path} failed: {exc}"
            ) from exc
        try:
            return json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SyncError(
                f"tenant {self.tenant.name}: Cortex API {path} returned invalid JSON"
            ) from exc

    def get_dataset_names(self) -> set[str]:
        response = self.post("/public_api/v1/xql/get_datasets", {})
        entries = unwrap_api_reply(response)
        if isinstance(entries, dict):
            entries = entries.get("data") or entries.get("datasets") or entries.get("reply")
        if not isinstance(entries, list):
            raise SyncError(f"tenant {self.tenant.name}: get_datasets response is invalid")
        names = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("Dataset Name") or entry.get("dataset_name") or entry.get("name")
            if name:
                names.add(str(name).lower())
        return names

    def add_dataset(self, spec: DatasetSpec) -> None:
        self.post(
            "/public_api/v1/xql/add_dataset",
            {
                "dataset_name": spec.name,
                "dataset_type": "lookup",
                "dataset_schema": spec.schema,
            },
        )

    def get_rows(self, dataset_name: str) -> list[dict[str, object]]:
        response = self.post(
            "/public_api/v1/xql/lookups/get_data",
            {
                "dataset_name": dataset_name,
                "filters": [],
                "limit": LOOKUP_READ_LIMIT,
            },
        )
        result = unwrap_api_reply(response)
        if not isinstance(result, dict) or not isinstance(result.get("data"), list):
            raise SyncError(
                f"tenant {self.tenant.name}: get_data response for {dataset_name} is invalid"
            )
        rows = result["data"]
        if not all(isinstance(row, dict) for row in rows):
            raise SyncError(
                f"tenant {self.tenant.name}: get_data for {dataset_name} returned invalid rows"
            )
        total = result.get("total_count", result.get("total count"))
        try:
            total_count = int(total)
        except (TypeError, ValueError) as exc:
            raise SyncError(
                f"tenant {self.tenant.name}: get_data for {dataset_name} omitted total_count"
            ) from exc
        if total_count != len(rows):
            raise SyncError(
                f"tenant {self.tenant.name}: {dataset_name} returned "
                f"{len(rows)} of {total_count} rows"
            )
        return rows

    def add_rows(
        self,
        spec: DatasetSpec,
        rows: list[dict[str, str]],
    ) -> None:
        self.post(
            "/public_api/v1/xql/lookups/add_data",
            {
                "dataset_name": spec.name,
                "data": rows,
            },
        )

    def remove_rows(self, spec: DatasetSpec, filters: list[dict[str, str]]) -> None:
        self.post(
            "/public_api/v1/xql/lookups/remove_data",
            {"dataset_name": spec.name, "filters": filters},
        )

class MutationLimiter:
    def __init__(self, interval_seconds: float, sleep: Callable[[float], None] = time.sleep):
        self.interval_seconds = interval_seconds
        self.sleep = sleep
        self.last_mutation: float | None = None

    def run(self, operation: Callable[[], None]) -> None:
        now = time.monotonic()
        if self.last_mutation is not None:
            delay = self.interval_seconds - (now - self.last_mutation)
            if delay > 0:
                self.sleep(delay)
        operation()
        self.last_mutation = time.monotonic()

def wait_for_dataset(
    client: CortexClient,
    dataset_name: str,
    timeout_seconds: float = DATASET_READY_TIMEOUT_SECONDS,
    poll_seconds: float = DATASET_READY_POLL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    deadline = monotonic() + timeout_seconds
    while True:
        if dataset_name.lower() in client.get_dataset_names():
            return
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise SyncError(f"Cortex dataset {dataset_name} was not ready within {timeout_seconds}s")
        sleep(min(poll_seconds, remaining))

def chunks(values: Iterable[dict[str, str]], size: int = 1000) -> Iterable[list[dict[str, str]]]:
    batch: list[dict[str, str]] = []
    for value in values:
        batch.append(value)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch

import os
import stat
def check_secret_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o037:
        raise SyncError(
            f"secret file {path} must not be group-writable or accessible by others; "
            "use mode 600 or 640"
        )
