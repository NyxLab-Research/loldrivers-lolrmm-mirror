#!/usr/bin/env python3
"""Synchronize mirrored LOLDrivers and LOLRMM data to Cortex XDR lookups."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import secrets
import stat
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_SOURCE_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "NyxLab-Research/loldrivers-lolrmm-mirror/main/data"
)
MAX_RESPONSE_BYTES = 50 * 1024 * 1024
LOOKUP_READ_LIMIT = 10_000
DATASET_READY_TIMEOUT_SECONDS = 90
DATASET_READY_POLL_SECONDS = 3
INTERNAL_CORTEX_FIELDS = {
    "_collector_name",
    "_collector_type",
    "_insert_time",
    "_time",
    "_update_time",
}
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


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


DATASET_SPECS = (
    DatasetSpec(
        name="loldrivers_hashes",
        filename="loldrivers_hashes.csv",
        fields=(
            "sha256",
            "sha1",
            "md5",
            "driver_name",
            "category",
            "verified",
            "source_id",
            "created",
        ),
        key_fields=("sha256",),
        manifest_count_field="driver_hash_rows",
        manifest_hash_field="loldrivers_csv_sha256",
    ),
    DatasetSpec(
        name="lolrmm_domains",
        filename="lolrmm_domains.csv",
        fields=("domain", "rmm_tool", "pattern", "regex"),
        key_fields=("pattern", "rmm_tool"),
        manifest_count_field="rmm_effective_rows",
        manifest_hash_field="lolrmm_csv_sha256",
    ),
)


@dataclass(frozen=True)
class Tenant:
    name: str
    api_fqdn: str
    api_key_id: str
    api_key: str
    api_key_type: str


@dataclass(frozen=True)
class Settings:
    source_base_url: str
    request_timeout_seconds: int
    mutation_interval_seconds: float
    max_delete_fraction: float


@dataclass(frozen=True)
class DatasetPlan:
    create_dataset: bool
    upsert_rows: tuple[dict[str, str], ...]
    stale_keys: tuple[dict[str, str], ...]
    current_count: int
    desired_count: int


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_limited(response: object, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    body = response.read(limit + 1)  # type: ignore[attr-defined]
    if len(body) > limit:
        raise SyncError(f"response exceeded {limit} bytes")
    return body


def fetch_bytes(url: str, timeout: int) -> bytes:
    request = Request(url, headers={"User-Agent": "nyxlab-cortex-lookup-sync/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = read_limited(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise SyncError(f"failed to download {url}: {exc}") from exc
    if not payload:
        raise SyncError(f"download returned an empty response: {url}")
    return payload


def validate_source_url(value: str) -> str:
    candidate = value.rstrip("/")
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise SyncError("source_base_url must be an HTTPS URL without query or fragment")
    return candidate


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


def check_secret_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o037:
        raise SyncError(
            f"secret file {path} must not be group-writable or accessible by others; "
            "use mode 600 or 640"
        )


def check_env_directory_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o027:
        raise SyncError(
            f"tenant env directory {path} must not be group-writable or accessible by others"
        )


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


def load_tenants(directory: Path) -> tuple[Tenant, ...]:
    if not directory.is_dir():
        raise SyncError(f"tenant env directory does not exist: {directory}")
    check_env_directory_permissions(directory)
    tenants: list[Tenant] = []
    names: set[str] = set()
    for path in sorted(directory.glob("*.env")):
        values = parse_env_file(path)
        if values.get("CORTEX_ENABLED", "true").lower() in {"0", "false", "no"}:
            continue
        name = values.get("CORTEX_TENANT_NAME", "").strip()
        api_key_id = values.get("CORTEX_API_KEY_ID", "").strip()
        api_key = values.get("CORTEX_API_KEY", "").strip()
        api_key_type = values.get("CORTEX_API_KEY_TYPE", "advanced").strip().lower()
        if not name or not api_key_id or not api_key:
            raise SyncError(
                f"{path}: CORTEX_TENANT_NAME, CORTEX_API_KEY_ID, and CORTEX_API_KEY are required"
            )
        if name in names:
            raise SyncError(f"duplicate tenant name: {name}")
        if api_key_type not in {"advanced", "standard"}:
            raise SyncError(f"{path}: CORTEX_API_KEY_TYPE must be advanced or standard")
        tenants.append(
            Tenant(
                name=name,
                api_fqdn=validate_api_fqdn(values.get("CORTEX_API_FQDN", "")),
                api_key_id=api_key_id,
                api_key=api_key,
                api_key_type=api_key_type,
            )
        )
        names.add(name)
    if not tenants:
        raise SyncError(f"no enabled *.env tenant files found in {directory}")
    return tuple(tenants)


def parse_csv(payload: bytes, spec: DatasetSpec) -> tuple[dict[str, str], ...]:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SyncError(f"{spec.filename} is not valid UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    if tuple(reader.fieldnames or ()) != spec.fields:
        raise SyncError(
            f"{spec.filename} fields do not match expected schema: {spec.fields}"
        )
    rows = tuple({field: str(row.get(field) or "") for field in spec.fields} for row in reader)
    if not rows:
        raise SyncError(f"{spec.filename} contained no rows")
    rows_by_key(rows, spec)
    return rows


def load_source_data(
    settings: Settings,
    source_dir: Path | None = None,
) -> dict[str, tuple[dict[str, str], ...]]:
    if source_dir is None:
        manifest_payload = fetch_bytes(
            f"{settings.source_base_url}/manifest.json",
            settings.request_timeout_seconds,
        )
    else:
        manifest_payload = (source_dir / "manifest.json").read_bytes()
    try:
        manifest = json.loads(manifest_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError("manifest.json is invalid") from exc
    if not isinstance(manifest, dict):
        raise SyncError("manifest.json root must be an object")

    datasets: dict[str, tuple[dict[str, str], ...]] = {}
    for spec in DATASET_SPECS:
        if source_dir is None:
            payload = fetch_bytes(
                f"{settings.source_base_url}/{spec.filename}",
                settings.request_timeout_seconds,
            )
        else:
            payload = (source_dir / spec.filename).read_bytes()
        expected_hash = str(manifest.get(spec.manifest_hash_field) or "")
        if not expected_hash or sha256_bytes(payload) != expected_hash:
            raise SyncError(f"{spec.filename} SHA256 does not match manifest.json")
        rows = parse_csv(payload, spec)
        expected_count = manifest.get(spec.manifest_count_field)
        if not isinstance(expected_count, int) or len(rows) != expected_count:
            raise SyncError(f"{spec.filename} row count does not match manifest.json")
        datasets[spec.name] = rows
    return datasets


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
            detail = read_limited(exc).decode("utf-8", errors="replace")[:1000]
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


def key_for(row: dict[str, str], spec: DatasetSpec) -> tuple[str, ...]:
    return tuple(row.get(field, "") for field in spec.key_fields)


def rows_by_key(
    rows: Iterable[dict[str, str]], spec: DatasetSpec
) -> dict[tuple[str, ...], dict[str, str]]:
    result: dict[tuple[str, ...], dict[str, str]] = {}
    for row in rows:
        key = key_for(row, spec)
        if not all(key):
            raise SyncError(f"{spec.name} contains a row with an empty key field")
        if key in result:
            raise SyncError(f"{spec.name} contains duplicate key {key}")
        result[key] = row
    return result


def normalize_cortex_rows(
    rows: Iterable[dict[str, object]], spec: DatasetSpec
) -> tuple[dict[str, str], ...]:
    normalized = []
    for source in rows:
        unexpected = set(source) - set(spec.fields) - INTERNAL_CORTEX_FIELDS
        if unexpected:
            raise SyncError(
                f"{spec.name} has an unexpected Cortex schema: {sorted(unexpected)}"
            )
        normalized.append(
            {
                field: "" if source.get(field) is None else str(source.get(field, ""))
                for field in spec.fields
            }
        )
    return tuple(normalized)


def build_plan(
    desired_rows: tuple[dict[str, str], ...],
    current_rows: tuple[dict[str, str], ...],
    spec: DatasetSpec,
    create_dataset: bool,
) -> DatasetPlan:
    desired = rows_by_key(desired_rows, spec)
    current = rows_by_key(current_rows, spec)
    upsert = tuple(
        desired[key]
        for key in sorted(desired)
        if key not in current or current[key] != desired[key]
    )
    stale = tuple(
        {field: current[key][field] for field in spec.key_fields}
        for key in sorted(set(current) - set(desired))
    )
    return DatasetPlan(
        create_dataset=create_dataset,
        upsert_rows=upsert,
        stale_keys=stale,
        current_count=len(current),
        desired_count=len(desired),
    )


def enforce_delete_guard(
    plan: DatasetPlan,
    spec: DatasetSpec,
    max_delete_fraction: float,
    allow_large_delete: bool,
) -> None:
    if allow_large_delete or not plan.current_count or not plan.stale_keys:
        return
    fraction = len(plan.stale_keys) / plan.current_count
    if fraction > max_delete_fraction:
        raise SyncError(
            f"{spec.name} would delete {len(plan.stale_keys)}/{plan.current_count} rows "
            f"({fraction:.1%}), above the {max_delete_fraction:.1%} safety limit"
        )


def verify_rows(
    actual_rows: Iterable[dict[str, object]],
    desired_rows: tuple[dict[str, str], ...],
    spec: DatasetSpec,
) -> None:
    actual = rows_by_key(normalize_cortex_rows(actual_rows, spec), spec)
    desired = rows_by_key(desired_rows, spec)
    if actual != desired:
        missing = len(set(desired) - set(actual))
        extra = len(set(actual) - set(desired))
        changed = sum(
            1 for key in set(actual) & set(desired) if actual[key] != desired[key]
        )
        raise SyncError(
            f"{spec.name} verification failed: missing={missing}, extra={extra}, changed={changed}"
        )


def sync_dataset(
    client: CortexClient,
    spec: DatasetSpec,
    desired_rows: tuple[dict[str, str], ...],
    dataset_exists: bool,
    limiter: MutationLimiter,
    max_delete_fraction: float,
    dry_run: bool,
    allow_large_delete: bool,
) -> DatasetPlan:
    current_api_rows = client.get_rows(spec.name) if dataset_exists else []
    current_rows = normalize_cortex_rows(current_api_rows, spec)
    plan = build_plan(desired_rows, current_rows, spec, not dataset_exists)
    enforce_delete_guard(plan, spec, max_delete_fraction, allow_large_delete)
    if dry_run:
        return plan

    if plan.create_dataset:
        limiter.run(lambda: client.add_dataset(spec))
        wait_for_dataset(client, spec.name)
    for batch in chunks(plan.upsert_rows):
        limiter.run(lambda batch=batch: client.add_rows(spec, batch))
    for batch in chunks(plan.stale_keys):
        limiter.run(lambda batch=batch: client.remove_rows(spec, batch))
    verify_rows(client.get_rows(spec.name), desired_rows, spec)
    return plan


def sync_tenant(
    tenant: Tenant,
    settings: Settings,
    source_data: dict[str, tuple[dict[str, str], ...]],
    dry_run: bool,
    allow_large_delete: bool,
) -> list[tuple[str, DatasetPlan]]:
    client = CortexClient(tenant, settings.request_timeout_seconds)
    existing = client.get_dataset_names()
    limiter = MutationLimiter(settings.mutation_interval_seconds)
    reports = []
    for spec in DATASET_SPECS:
        plan = sync_dataset(
            client=client,
            spec=spec,
            desired_rows=source_data[spec.name],
            dataset_exists=spec.name.lower() in existing,
            limiter=limiter,
            max_delete_fraction=settings.max_delete_fraction,
            dry_run=dry_run,
            allow_large_delete=allow_large_delete,
        )
        reports.append((spec.name, plan))
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-dir", type=Path, required=True)
    parser.add_argument("--source-base-url", default=DEFAULT_SOURCE_BASE_URL)
    parser.add_argument("--request-timeout-seconds", type=int, default=120)
    parser.add_argument("--mutation-interval-seconds", type=float, default=10)
    parser.add_argument("--max-delete-fraction", type=float, default=0.25)
    parser.add_argument(
        "--source-dir",
        type=Path,
        help="Read manifest and CSV files locally instead of downloading the public mirror",
    )
    parser.add_argument("--tenant", action="append", default=[], help="Sync only the named tenant")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-large-delete", action="store_true")
    args = parser.parse_args()

    try:
        if args.request_timeout_seconds < 1:
            raise SyncError("request timeout must be positive")
        if args.mutation_interval_seconds < 0:
            raise SyncError("mutation interval cannot be negative")
        if not 0 <= args.max_delete_fraction <= 1:
            raise SyncError("max delete fraction must be between 0 and 1")
        settings = Settings(
            source_base_url=validate_source_url(args.source_base_url),
            request_timeout_seconds=args.request_timeout_seconds,
            mutation_interval_seconds=args.mutation_interval_seconds,
            max_delete_fraction=args.max_delete_fraction,
        )
        configured_tenants = load_tenants(args.env_dir)
        source_data = load_source_data(settings, args.source_dir)
    except (OSError, SyncError, ValueError) as exc:
        print(f"sync failed: {exc}", file=sys.stderr)
        return 1

    selected_names = set(args.tenant)
    tenants = [
        tenant
        for tenant in configured_tenants
        if not selected_names or tenant.name in selected_names
    ]
    missing_names = selected_names - {tenant.name for tenant in tenants}
    if missing_names:
        print(f"sync failed: unknown or disabled tenants: {sorted(missing_names)}", file=sys.stderr)
        return 1

    failures = []
    for tenant in tenants:
        print(f"[{tenant.name}] starting{' dry run' if args.dry_run else ''}")
        try:
            reports = sync_tenant(
                tenant,
                settings,
                source_data,
                dry_run=args.dry_run,
                allow_large_delete=args.allow_large_delete,
            )
            for dataset_name, plan in reports:
                print(
                    f"[{tenant.name}] {dataset_name}: create={plan.create_dataset} "
                    f"upsert={len(plan.upsert_rows)} delete={len(plan.stale_keys)} "
                    f"final={plan.desired_count}"
                )
        except (OSError, SyncError, ValueError) as exc:
            failures.append(tenant.name)
            print(f"[{tenant.name}] failed: {exc}", file=sys.stderr)
    if failures:
        print(f"sync completed with failed tenants: {', '.join(failures)}", file=sys.stderr)
        return 1
    print(f"sync completed successfully for {len(tenants)} tenant(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
