<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://rolepass.dev/assets/logo-indigo.svg">
    <img src="https://rolepass.dev/assets/logo-ink.svg" alt="RolePass" width="96">
  </picture>
</p>

# RolePass

Manage AWS IAM roles for CI/CD pipelines across multiple accounts using OIDC federation.

RolePass replaces hand-managed IAM roles and long-lived access keys with a single declarative config. Define your roles once, preview the exact changes, and apply them to any number of AWS accounts.

**Documentation: [rolepass.dev](https://rolepass.dev)**

## Features

- **Multi-account**: deploy roles to any number of AWS accounts from a single config
- **GitHub & GitLab OIDC**: federated trust policies with support for self-hosted instances
- **Declarative YAML config**: define roles, permissions, and trust in version-controlled files
- **Plan before apply**: preview exactly what will be created, updated, or deleted
- **Orphan detection**: automatically finds rolepass-managed roles that are no longer in config
- **Partition support**: works with the `aws`, `aws-cn`, `aws-us-gov`, and `aws-eusc` partitions

## Installation

Download a prebuilt binary from [releases.rolepass.dev](https://releases.rolepass.dev) (Linux x86-64/ARM64 in glibc and musl variants, macOS Apple Silicon, Windows x86-64):

```sh
curl -LO https://releases.rolepass.dev/latest/rolepass-aarch64-apple-darwin.tar.xz
tar -xf rolepass-aarch64-apple-darwin.tar.xz
sudo mv rolepass /usr/local/bin/
```

Or build from source:

```sh
cargo install --path .
```

Or use Docker:

```sh
docker build -t rolepass .
docker run --rm -v "$PWD:/config" -w /config rolepass validate
```

See the [installation guide](https://rolepass.dev/guides/installation/) for all platforms and details.

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

Each target account needs a one-time bootstrapped deployer role and OIDC provider. See the [bootstrapping guide](https://rolepass.dev/guides/bootstrapping/). For configuration reference, CI examples, and day-to-day workflow, head to [rolepass.dev](https://rolepass.dev).

## License

[MIT](LICENSE)
