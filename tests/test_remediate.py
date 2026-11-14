"""Unit tests for container security remediation helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from remediate import split_image_ref, summarize_trivy_json, update_dockerfile_digests


def test_split_image_ref() -> None:
    assert split_image_ref("python") == ("registry-1.docker.io", "library/python")
    assert split_image_ref("myorg/app") == ("registry-1.docker.io", "myorg/app")
    assert split_image_ref("ghcr.io/astral-sh/uv") == ("ghcr.io", "astral-sh/uv")
    assert split_image_ref("docker.io/library/nginx") == ("registry-1.docker.io", "library/nginx")


def test_update_dockerfile_digests_pins_and_updates() -> None:
    dockerfile = (
        "FROM python:3.15-slim AS builder\n"
        "COPY --from=ghcr.io/astral-sh/uv:0.8.4@sha256:" + "0" * 64 + " /uv /bin/uv\n"
        "FROM scratch\n"
    )

    def fake_resolver(image: str, tag: str) -> str:
        if image == "python":
            return "sha256:" + "a" * 64
        if image == "ghcr.io/astral-sh/uv":
            return "sha256:" + "b" * 64
        raise AssertionError(f"Unexpected image: {image}:{tag}")

    updated, changes = update_dockerfile_digests(dockerfile, resolver=fake_resolver)
    assert f"FROM python:3.15-slim@sha256:{'a' * 64} AS builder\n" in updated
    assert f"COPY --from=ghcr.io/astral-sh/uv:0.8.4@sha256:{'b' * 64} /uv /bin/uv\n" in updated
    assert "FROM scratch\n" in updated
    assert len(changes) == 2


def test_summarize_trivy_json(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2026-0001", "PkgName": "openssl", "FixedVersion": "3.0.2"},
                            {"Severity": "HIGH", "VulnerabilityID": "CVE-2026-0002", "PkgName": "zlib", "FixedVersion": "1.3.1"},
                            {"Severity": "LOW", "VulnerabilityID": "CVE-2026-0003", "PkgName": "curl"},
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    summary, details = summarize_trivy_json(report)
    assert summary.critical == 1
    assert summary.high == 1
    assert summary.medium == 0
    assert summary.low == 1
    assert summary.tracked_total == 2
    assert len(details) == 2
