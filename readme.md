# rolepass

Manage AWS IAM roles for CI/CD pipelines across multiple accounts using OIDC federation.

## Features

- **Multi-account** — deploy roles to any number of AWS accounts from a single config
- **GitHub & GitLab OIDC** — federated trust policies with support for self-hosted instances
- **Declarative YAML config** — define roles, permissions, and trust in version-controlled files
- **Plan before apply** — preview exactly what will be created, updated, or deleted
- **Orphan detection** — automatically finds rolepass-managed roles that are no longer in config
- **Partition support** — works with `aws`, `aws-cn`, and `aws-us-gov` partitions

## Quick Start

```sh
# Scaffold a new project
rolepass init

# Edit accounts.yaml and roles/deploy.yaml for your environment

# Validate config files
rolepass validate

# See what would change (requires AWS credentials)
rolepass plan

# Apply changes
rolepass apply
```

## Installation

### From source

```sh
cargo install --path .
```

### Docker

```sh
docker build -t rolepass .
docker run --rm -v "$PWD:/config" -w /config rolepass validate
```

## CLI Reference

```
rolepass [OPTIONS] <COMMAND>
```

### Commands

| Command    | Description                                              |
|------------|----------------------------------------------------------|
| `init`     | Initialize a new project with sample config files        |
| `validate` | Validate config files without making AWS calls           |
| `preview`  | Preview the generated IAM role JSON without making AWS calls |
| `plan`     | Show what changes would be made (requires AWS credentials) |
| `apply`    | Deploy roles to AWS accounts (requires AWS credentials)  |

### Global Options

| Option               | Env Var                | Default | Description                  |
|----------------------|------------------------|---------|------------------------------|
| `--config-dir <DIR>` | `ROLEPASS_CONFIG_DIR`  | `.`     | Config directory             |
| `--accounts <FILE>`  | `ROLEPASS_ACCOUNTS`    |         | Override accounts file path  |
| `--roles <FILE>,...`  | `ROLEPASS_ROLES`       |         | Override role file paths (comma-separated) |

### Apply Flags

| Flag        | Description              |
|-------------|--------------------------|
| `--yes, -y` | Skip confirmation prompt |

## Configuration

By default, rolepass looks for:
- `<config-dir>/accounts.yaml` — account registry
- `<config-dir>/roles/*.yaml` — role definitions (auto-discovered, sorted alphabetically)

### accounts.yaml

Defines the AWS accounts rolepass manages roles in.

```yaml
accounts:
  - name: production
    id: "123456789012"
  - name: staging
    id: "123456789013"
```

| Field                | Required | Default              | Description                                             |
|----------------------|----------|----------------------|---------------------------------------------------------|
| `name`               | yes      |                      | Unique short name (`[a-z0-9-]`, max 32 chars), used in role definitions |
| `id`                 | yes      |                      | 12-digit AWS account ID                                 |
| `partition`          | no       | `aws`                | AWS partition: `aws`, `aws-cn`, or `aws-us-gov`         |
| `deployer_role_name` | no       | `rolepass-deployer`  | Name of the bootstrapped IAM role rolepass assumes      |

### Role files

Each file in `roles/` defines one IAM role.

```yaml
name: deploy
description: CI/CD deployment role
accounts:
  - production
trust:
  provider: github
  repo: my-org/my-repo
  refs:
    - refs/heads/main
permissions:
  - effect: Allow
    actions:
      - sts:GetCallerIdentity
    resources:
      - "*"
```

| Field                  | Required | Default | Description                                                  |
|------------------------|----------|---------|--------------------------------------------------------------|
| `name`                 | yes      |         | IAM role name (must be unique per account)                   |
| `description`          | no       |         | Human-readable description                                   |
| `accounts`             | yes      |         | List of account names from accounts.yaml                     |
| `trust.provider`       | yes      |         | `github` or `gitlab`                                         |
| `trust.repo`           | yes      |         | Repository path as it appears in the OIDC subject claim      |
| `trust.issuer`         | no       | *auto*  | OIDC issuer hostname (without `https://`). Defaults to `token.actions.githubusercontent.com` for GitHub, `gitlab.com` for GitLab |
| `trust.refs`           | no       |         | Git refs allowed to assume the role (supports wildcards, e.g. `refs/heads/*`) |
| `permissions`          | yes      |         | List of IAM policy statements                                |
| `permissions[].effect` | yes      |         | `Allow` or `Deny`                                            |
| `permissions[].actions`| yes      |         | IAM actions (e.g. `s3:*`, `lambda:InvokeFunction`)           |
| `permissions[].resources`| yes    |         | Resource ARNs (supports wildcards)                           |
| `permissions[].conditions`| no    |         | IAM condition block                                          |
| `max_session_duration` | no       | `3600`  | Maximum session duration in seconds (3600–43200)             |

## Prerequisites

1. **AWS credentials** — rolepass uses the default AWS credential chain. Your credentials must be able to call `sts:AssumeRole` on the deployer role in each target account.

2. **Deployer role** — each target account needs a bootstrapped IAM role (default name: `rolepass-deployer`) that rolepass assumes to manage roles. This deployer role needs permissions to create, update, delete, and tag IAM roles and inline policies.

3. **OIDC identity provider** — each target account needs the relevant OIDC provider registered (e.g. `token.actions.githubusercontent.com` for GitHub Actions).

## How It Works

1. **Validate** — config files are loaded and validated against JSON schemas, including cross-validation that all account references in role files exist in the accounts registry
2. **Assume deployer roles** — rolepass assumes the deployer role in each target account via STS
3. **Diff** — for each role/account pair, the current IAM state is fetched and compared against the desired state (trust policy, permission policy, session duration, description)
4. **Plan** — changes are categorized as create, update, delete, or no-change. Orphaned roles (tagged `managed-by:rolepass` but no longer in config) are flagged for deletion
5. **Apply** — after confirmation, IAM operations are executed: roles are created/updated/deleted as needed. All managed roles are tagged `managed-by:rolepass`
