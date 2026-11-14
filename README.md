# shared-workflows

Shared GitHub Actions reusable workflows for container security scanning and automated PR remediation.

## Workflows

### `container-security-remediate.yml`

Scans a container image with Trivy, updates `Dockerfile` base image `@sha256` digests (and optionally upgrades lockfiles), re-scans to verify improvement, opens/updates a PR, and dispatches the repository's CI workflow on the remediation branch.

#### Example caller workflow

```yaml
name: Container security

on:
  schedule:
    - cron: '30 1 * * 5'
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  issues: write
  actions: write

concurrency:
  group: container-security
  cancel-in-progress: false

jobs:
  remediate:
    uses: WisChang005/shared-workflows/.github/workflows/container-security-remediate.yml@v1
    with:
      image_name: my-app
      ci_workflow: ci.yml
```

> **Repository setting required:** Under **Settings → Actions → General → Workflow permissions**, enable **Allow GitHub Actions to create and approve pull requests** (or pass a PAT via `secrets.pr_token`).
