"""Helpers for container base image digest updates and Trivy report comparison."""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

FROM_IMAGE_RE = re.compile(
    r"^(?P<prefix>\s*FROM\s+(?:--platform=\S+\s+)?)"
    r"(?P<image>[a-zA-Z0-9._/-]+):(?P<tag>[a-zA-Z0-9._-]+)"
    r"(?:@sha256:[a-fA-F0-9]{64})?"
    r"(?P<suffix>(?:\s+AS\s+\S+)?\s*(?:#.*)?)$",
    re.IGNORECASE,
)

COPY_FROM_IMAGE_RE = re.compile(
    r"^(?P<prefix>\s*COPY\s+.*?--from=)"
    r"(?P<image>[a-zA-Z0-9._/-]+):(?P<tag>[a-zA-Z0-9._-]+)"
    r"(?:@sha256:[a-fA-F0-9]{64})?"
    r"(?P<suffix>\s+.*)$",
    re.IGNORECASE,
)

WWW_AUTH_RE = re.compile(r'(\w+)="([^"]*)"')
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)


@dataclass(frozen=True)
class VulnSummary:
    """Counts of vulnerabilities grouped by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def tracked_total(self) -> int:
        return self.critical + self.high + self.medium


def split_image_ref(image: str) -> tuple[str, str]:
    """Split an image name into (registry_host, repository_path)."""
    parts = image.split("/", 1)
    if len(parts) == 1:
        return "registry-1.docker.io", f"library/{image}"
    first, rest = parts
    if "." in first or ":" in first or first == "localhost":
        host = "registry-1.docker.io" if first == "docker.io" else first
        if host == "registry-1.docker.io" and "/" not in rest:
            rest = f"library/{rest}"
        return host, rest
    return "registry-1.docker.io", image


def _fetch_bearer_token(www_auth: str) -> str | None:
    if not www_auth.lower().startswith("bearer "):
        return None
    params = dict(WWW_AUTH_RE.findall(www_auth))
    realm = params.get("realm")
    if not realm:
        return None
    query_parts = [
        f"{k}={urllib.request.quote(v, safe=':/')}"
        for k, v in params.items()
        if k in {"service", "scope"}
    ]
    url = f"{realm}?{'&'.join(query_parts)}" if query_parts else realm
    with urllib.request.urlopen(url, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("token") or data.get("access_token")


def fetch_latest_digest(image: str, tag: str) -> str:
    """Resolve the current manifest digest for image:tag via Registry HTTP API v2."""
    host, repo = split_image_ref(image)
    url = f"https://{host}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": MANIFEST_ACCEPT}

    req = urllib.request.Request(url, method="HEAD", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            digest = resp.headers.get("Docker-Content-Digest")
            if digest:
                return digest
    except urllib.error.HTTPError as err:
        if err.code != 401:
            raise
        token = _fetch_bearer_token(err.headers.get("WWW-Authenticate", ""))
        if not token:
            raise
        authed_req = urllib.request.Request(
            url,
            method="HEAD",
            headers={**headers, "Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(authed_req, timeout=15) as resp:
            digest = resp.headers.get("Docker-Content-Digest")
            if digest:
                return digest

    raise RuntimeError(f"Missing Docker-Content-Digest header for {image}:{tag}")


def update_dockerfile_digests(content: str, resolver=fetch_latest_digest) -> tuple[str, list[str]]:
    """Update or pin @sha256 digests on FROM and COPY --from lines."""
    updated_lines: list[str] = []
    changes: list[str] = []
    cache: dict[tuple[str, str], str] = {}

    for line in content.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        stripped = line[:-1] if newline else line

        matched = FROM_IMAGE_RE.match(stripped) or COPY_FROM_IMAGE_RE.match(stripped)
        if not matched:
            updated_lines.append(line)
            continue

        image = matched.group("image")
        tag = matched.group("tag")
        if image.lower() == "scratch":
            updated_lines.append(line)
            continue

        key = (image, tag)
        if key not in cache:
            cache[key] = resolver(image, tag)
        digest = cache[key]

        new_line = f"{matched.group('prefix')}{image}:{tag}@{digest}{matched.group('suffix')}{newline}"
        if new_line != line:
            changes.append(f"{image}:{tag} -> {digest}")
        updated_lines.append(new_line)

    return "".join(updated_lines), changes


def summarize_trivy_json(report_path: Path) -> tuple[VulnSummary, list[str]]:
    """Summarize vulnerabilities from a Trivy JSON report."""
    if not report_path.exists():
        return VulnSummary(), []

    raw = report_path.read_text(encoding="utf-8").strip()
    if not raw:
        return VulnSummary(), []

    data = json.loads(raw)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    seen: set[tuple[str, str, str]] = set()
    details: list[str] = []

    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = str(vuln.get("Severity", "")).upper()
            vid = str(vuln.get("VulnerabilityID", ""))
            pkg = str(vuln.get("PkgName", ""))
            if sev in counts:
                counts[sev] += 1
            key = (sev, vid, pkg)
            if key not in seen and sev in {"CRITICAL", "HIGH", "MEDIUM"}:
                seen.add(key)
                fixed = vuln.get("FixedVersion") or "unfixed"
                details.append(f"- `{sev}` **{vid}** in `{pkg}` (fixed: `{fixed}`)")

    summary = VulnSummary(
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
    )
    return summary, details[:30]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: remediate.py <update-dockerfile|summarize> ...", file=sys.stderr)
        return 2

    cmd = argv[1]
    if cmd == "update-dockerfile":
        dockerfile_path = Path(argv[2] if len(argv) > 2 else "Dockerfile")
        original = dockerfile_path.read_text(encoding="utf-8")
        updated, changes = update_dockerfile_digests(original)
        if updated != original:
            dockerfile_path.write_text(updated, encoding="utf-8")
        print(json.dumps({"changed": updated != original, "changes": changes}))
        return 0

    if cmd == "summarize":
        baseline_path = Path(argv[2])
        after_path = Path(argv[3]) if len(argv) > 3 else None
        base_sum, base_details = summarize_trivy_json(baseline_path)
        payload: dict[str, object] = {
            "baseline": {
                "critical": base_sum.critical,
                "high": base_sum.high,
                "medium": base_sum.medium,
                "tracked_total": base_sum.tracked_total,
            },
            "baseline_details": base_details,
        }
        if after_path is not None:
            after_sum, after_details = summarize_trivy_json(after_path)
            payload["after"] = {
                "critical": after_sum.critical,
                "high": after_sum.high,
                "medium": after_sum.medium,
                "tracked_total": after_sum.tracked_total,
            }
            payload["after_details"] = after_details
            payload["reduced"] = after_sum.tracked_total < base_sum.tracked_total
        print(json.dumps(payload))
        return 0

    print(f"Unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
