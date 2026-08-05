#!/usr/bin/env python3
"""Mirror LOLDrivers/LOLRMM data and build query-friendly CSV files.

The script intentionally uses only the Python standard library so it can run in
GitHub Actions and on a customer's jump host without a dependency install.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable
from urllib.request import Request, urlopen


DRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
RMM_URL = "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_domains.csv"
USER_AGENT = "loldrivers-lolrmm-mirror/1.0"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
MD5_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
DEFAULT_RMM_EXCLUSIONS_FILE = (
    Path(__file__).resolve().parents[1] / "config" / "lolrmm_domain_exclusions.csv"
)


def fetch(url: str) -> bytes:
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "gzip"},
    )
    with urlopen(request, timeout=120) as response:  # noqa: S310 - URLs are constants/CLI overrides.
        body = response.read(MAX_DOWNLOAD_BYTES + 1)
        content_encoding = response.headers.get("Content-Encoding", "").lower()
    if len(body) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"upstream response exceeded {MAX_DOWNLOAD_BYTES} bytes: {url}")
    if content_encoding == "gzip":
        body = gzip.decompress(body)
    if len(body) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"decompressed response exceeded {MAX_DOWNLOAD_BYTES} bytes: {url}")
    if not body:
        raise ValueError(f"upstream returned an empty response: {url}")
    return body


def clean(value: object) -> str:
    return str(value or "").strip()


def unique_text(values: Iterable[object]) -> str:
    result = sorted({clean(value) for value in values if clean(value)})
    return ";".join(result)


def valid_hash(value: object, pattern: re.Pattern[str]) -> str:
    candidate = clean(value).lower()
    return candidate if pattern.fullmatch(candidate) else ""


def driver_rows(payload: bytes) -> list[dict[str, str]]:
    records = json.loads(payload.decode("utf-8-sig"))
    if not isinstance(records, list):
        raise ValueError("LOLDrivers JSON root must be an array")

    grouped: dict[str, dict[str, list[str] | str]] = {}
    for driver in records:
        if not isinstance(driver, dict):
            continue
        tags = driver.get("Tags") or []
        if not isinstance(tags, list):
            tags = [tags]
        samples = driver.get("KnownVulnerableSamples") or []
        if not isinstance(samples, list):
            samples = []
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            sha256 = valid_hash(sample.get("SHA256"), SHA256_RE)
            if not sha256:
                continue
            row = grouped.setdefault(
                sha256,
                {
                    "sha1": [],
                    "md5": [],
                    "driver_name": [],
                    "category": [],
                    "verified": [],
                    "source_id": [],
                    "created": [],
                },
            )
            sha1 = valid_hash(sample.get("SHA1"), SHA1_RE)
            md5 = valid_hash(sample.get("MD5"), MD5_RE)
            if sha1:
                row["sha1"].append(sha1)  # type: ignore[union-attr]
            if md5:
                row["md5"].append(md5)  # type: ignore[union-attr]
            row["driver_name"].extend(  # type: ignore[union-attr]
                [sample.get("Filename"), sample.get("OriginalFilename"), *tags]
            )
            row["category"].append(driver.get("Category"))  # type: ignore[union-attr]
            row["verified"].append(driver.get("Verified"))  # type: ignore[union-attr]
            row["source_id"].append(driver.get("Id"))  # type: ignore[union-attr]
            row["created"].append(driver.get("Created"))  # type: ignore[union-attr]

    output = []
    for sha256 in sorted(grouped):
        row = grouped[sha256]
        output.append(
            {
                "sha256": sha256,
                "sha1": unique_text(row["sha1"]),
                "md5": unique_text(row["md5"]),
                "driver_name": unique_text(row["driver_name"]),
                "category": unique_text(row["category"]),
                "verified": unique_text(row["verified"]),
                "source_id": unique_text(row["source_id"]),
                "created": unique_text(row["created"]),
            }
        )
    if not output:
        raise ValueError("LOLDrivers JSON contained no valid SHA256 samples")
    return output


def strip_host(value: str) -> str:
    value = clean(value).lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0]
    # The Cortex external hostname field is a host, not host:port.
    value = re.sub(r":\d+$", "", value)
    return value.rstrip(".")


def glob_regex(pattern: str) -> str:
    """Convert the source's glob/regex-like URI into an anchored RE2 pattern."""
    pattern = strip_host(pattern)
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            out.append(".*")
        elif char == "[":
            end = pattern.find("]", index + 1)
            if end == -1:
                out.append(r"\[")
            else:
                out.append(pattern[index : end + 1])
                index = end
        elif char == "{":
            end = pattern.find("}", index + 1)
            if end == -1:
                out.append(r"\{")
            else:
                out.append(pattern[index : end + 1])
                index = end
        elif char in ".+?()|^$\\":
            out.append("\\" + char)
        else:
            out.append(char)
        index += 1
    return "^(?:" + "".join(out) + ")$"


def domain_root(pattern: str) -> str:
    """Return a suffix suitable for a conservative host-domain match.

    Leading `*.` patterns retain the full domain. Embedded globs/regexes are
    reduced to their final two labels; the complete regex remains in `regex`.
    """
    host = strip_host(pattern)
    if not host:
        return ""
    if host.startswith("*."):
        return host[2:]
    if "*" not in host and "[" not in host and "{" not in host:
        return host
    labels = [part for part in re.split(r"\.", host) if part]
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""


def rmm_rows(payload: bytes) -> list[dict[str, str]]:
    text = payload.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    expected = {"URI", "RMM_Tool"}
    if not reader.fieldnames or not expected.issubset(reader.fieldnames):
        raise ValueError("LOLRMM CSV must contain URI and RMM_Tool columns")
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for source in reader:
        pattern = clean(source.get("URI"))
        tool = clean(source.get("RMM_Tool"))
        if not pattern or not tool:
            continue
        key = (pattern.lower(), tool)
        rows[key] = {
            "domain": domain_root(pattern),
            "rmm_tool": tool,
            "pattern": pattern.lower(),
            "regex": glob_regex(pattern),
        }
    output = sorted(rows.values(), key=lambda row: (row["domain"], row["rmm_tool"], row["pattern"]))
    if not output:
        raise ValueError("LOLRMM CSV contained no usable rows")
    return output


def load_rmm_exclusions(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ValueError(f"RMM exclusion file does not exist: {path}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = {"domain", "reason"}
        if not reader.fieldnames or not expected.issubset(reader.fieldnames):
            raise ValueError("RMM exclusion CSV must contain domain and reason columns")
        exclusions: dict[str, str] = {}
        for source in reader:
            domain = strip_host(clean(source.get("domain")))
            reason = clean(source.get("reason"))
            if not domain or not reason:
                raise ValueError("RMM exclusion rows require both domain and reason")
            exclusions[domain] = reason
    return exclusions


def filter_rmm_rows(
    rows: list[dict[str, str]], exclusions: dict[str, str]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    effective: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    for row in rows:
        reason = exclusions.get(row["domain"])
        if reason:
            excluded.append({**row, "exclusion_reason": reason})
        else:
            effective.append(row)
    return effective, excluded


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temp_name = Path(handle.name)
    temp_name.replace(path)


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    write_bytes(path, buffer.getvalue().encode("utf-8"))


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sync(
    output_dir: Path,
    drivers_url: str = DRIVERS_URL,
    rmm_url: str = RMM_URL,
    rmm_exclusions_file: Path = DEFAULT_RMM_EXCLUSIONS_FILE,
) -> dict[str, int]:
    drivers_payload = fetch(drivers_url)
    rmm_payload = fetch(rmm_url)
    drivers = driver_rows(drivers_payload)
    upstream_domains = rmm_rows(rmm_payload)
    exclusions = load_rmm_exclusions(rmm_exclusions_file)
    domains, excluded_domains = filter_rmm_rows(upstream_domains, exclusions)

    raw_dir = output_dir / "raw"
    write_bytes(raw_dir / "drivers.json", drivers_payload)
    write_bytes(raw_dir / "rmm_domains.csv", rmm_payload)
    write_csv(
        output_dir / "loldrivers_hashes.csv",
        drivers,
        ["sha256", "sha1", "md5", "driver_name", "category", "verified", "source_id", "created"],
    )
    write_csv(output_dir / "lolrmm_domains.csv", domains, ["domain", "rmm_tool", "pattern", "regex"])
    write_bytes(output_dir / "manifest.json", json.dumps({
        "drivers_url": drivers_url,
        "rmm_url": rmm_url,
        "drivers_sha256": sha256_bytes(drivers_payload),
        "rmm_sha256": sha256_bytes(rmm_payload),
        "driver_hash_rows": len(drivers),
        "rmm_domain_rows": len(domains),
        "rmm_upstream_rows": len(upstream_domains),
        "rmm_excluded_rows": len(excluded_domains),
        "rmm_effective_rows": len(domains),
    }, indent=2, sort_keys=True).encode("utf-8"))
    return {
        "driver_hash_rows": len(drivers),
        "rmm_domain_rows": len(domains),
        "rmm_upstream_rows": len(upstream_domains),
        "rmm_excluded_rows": len(excluded_domains),
        "rmm_effective_rows": len(domains),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("data"))
    parser.add_argument("--drivers-url", default=DRIVERS_URL)
    parser.add_argument("--rmm-url", default=RMM_URL)
    parser.add_argument("--rmm-exclusions", type=Path, default=DEFAULT_RMM_EXCLUSIONS_FILE)
    args = parser.parse_args()
    try:
        summary = sync(args.output_dir, args.drivers_url, args.rmm_url, args.rmm_exclusions)
    except Exception as exc:  # noqa: BLE001 - CLI should show a concise failure and non-zero status.
        print(f"sync failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"synced {summary['driver_hash_rows']} unique driver hashes and "
        f"{summary['rmm_effective_rows']} effective RMM rows "
        f"({summary['rmm_excluded_rows']} excluded from "
        f"{summary['rmm_upstream_rows']} normalized upstream rows)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
