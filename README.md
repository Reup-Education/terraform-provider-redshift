# Terraform Provider for AWS Redshift (ReUp fork — adding role support)

> [!NOTE]
> This is ReUp Education's fork of [serenityzn/terraform-provider-redshift](https://github.com/serenityzn/terraform-provider-redshift), which is itself a fork of the original, now-deprecated [brainly/terraform-provider-redshift](https://github.com/brainly/terraform-provider-redshift).
>
> **Upstream (serenityzn) status:** Actively maintained, adds Redshift Serverless support on top of the original brainly feature set.
>
> **This fork:** Adds support for Redshift's role-based access control (`CREATE ROLE` / `GRANT ROLE` / role assignment) — not yet available upstream. Once stable, we intend to upstream this as a PR to serenityzn/terraform-provider-redshift; this fork exists independently in case that PR isn't accepted.

This provider allows you to manage [AWS Redshift](https://aws.amazon.com/redshift/) objects with Terraform — users, groups, roles, schemas, grants, databases, and more — for both provisioned clusters and Redshift Serverless.

The upstream provider is published on the [Terraform registry](https://registry.terraform.io/providers/serenityzn/redshift/latest/docs). This fork is not (yet) published there — see [Building The Provider](#building-the-provider) for using it directly from source until it is upstreamed or published independently.

## Features

- **Role support (this fork)**: Manage Redshift roles and role-based access control (RBAC) with three new resources — `redshift_role` (create/rename/drop roles), `redshift_role_system_privileges` (grant system-level privileges to a role), and `redshift_role_grant` (assign a role to a user or to another role, including nested role hierarchies). See [`docs/resources/role.md`](docs/resources/role.md), [`docs/resources/role_system_privileges.md`](docs/resources/role_system_privileges.md), and [`docs/resources/role_grant.md`](docs/resources/role_grant.md).
- **Redshift Serverless Support**: Use `type = "serverless"` for Redshift Serverless deployments
- **IAM Temporary Credentials for Serverless**: Use `temporary_credentials_serverless` to authenticate via AWS IAM without storing passwords
- **IAM Temporary Credentials for Provisioned**: Use `temporary_credentials` to authenticate via `redshift:GetClusterCredentials`
- **Static Credentials**: Username/password authentication for both provisioned and serverless
- **Backward Compatibility**: All original features continue to work for regular Redshift clusters

---

## Provider Configuration

### Redshift Serverless — IAM Temporary Credentials (recommended)

Uses `redshift-serverless:GetCredentials` to obtain ephemeral credentials from AWS. No password is stored or managed.

```hcl
provider "redshift" {
  host     = "your-workgroup.123456789012.us-east-1.redshift-serverless.amazonaws.com"
  database = "your_database"
  type     = "serverless"

  temporary_credentials_serverless {
    workgroup_name = "your-workgroup"
    region         = "us-east-1"
  }
}
```

With cross-account role assumption:

```hcl
provider "redshift" {
  host     = "your-workgroup.123456789012.us-east-1.redshift-serverless.amazonaws.com"
  database = "your_database"
  type     = "serverless"

  temporary_credentials_serverless {
    workgroup_name = "your-workgroup"
    region         = "us-east-1"
    assume_role {
      arn = "arn:aws:iam::012345678901:role/role-name"
    }
  }
}
```

### Redshift Serverless — Static Credentials

```hcl
provider "redshift" {
  host     = "your-workgroup.123456789012.us-east-1.redshift-serverless.amazonaws.com"
  username = "admin"
  password = "your_password"
  database = "your_database"
  type     = "serverless"
}
```

### Provisioned Cluster — IAM Temporary Credentials

```hcl
provider "redshift" {
  host     = "your-cluster.redshift.amazonaws.com"
  username = "your_username"

  temporary_credentials {
    cluster_identifier = "my-cluster"
    region             = "us-east-1"
  }
}
```

### Provisioned Cluster — Static Credentials

```hcl
provider "redshift" {
  host     = "your-cluster.redshift.amazonaws.com"
  username = "your_username"
  password = "your_password"
  database = "your_database"
}
```

---

## Role-Based Access Control (RBAC)

This fork adds three resources to manage Amazon Redshift's [role-based access control](https://docs.aws.amazon.com/redshift/latest/dg/t_Roles.html):

```hcl
resource "redshift_role" "data_engineer" {
  name = "data_engineer"
}

# Let the role create/drop schemas and tables without superuser access
resource "redshift_role_system_privileges" "data_engineer" {
  role       = redshift_role.data_engineer.name
  privileges = ["create schema", "drop schema", "create table", "drop table", "alter table"]
}

# Assign the role to a user
resource "redshift_role_grant" "data_engineer_to_alice" {
  role = redshift_role.data_engineer.name
  user = redshift_user.alice.name
}

# Roles can also be nested by granting one role to another
resource "redshift_role_grant" "data_engineer_to_analyst" {
  role         = redshift_role.data_engineer.name
  grantee_role = redshift_role.analyst.name
}

# Object-level privileges (tables, schemas, databases, functions, procedures,
# languages) can also be granted directly to a role with redshift_grant
resource "redshift_grant" "data_engineer_schema_access" {
  role        = redshift_role.data_engineer.name
  schema      = "my_schema"
  object_type = "schema"
  privileges  = ["create", "usage"]
}

# Default privileges (applied automatically to future objects) can be granted
# to a role too, so new tables don't need a redshift_grant every time
resource "redshift_default_privileges" "data_engineer_defaults" {
  role        = redshift_role.data_engineer.name
  owner       = "root"
  schema      = "my_schema"
  object_type = "table"
  privileges  = ["select", "insert"]
}
```

## IAM Temporary Credentials — How It Works

When using `temporary_credentials_serverless`, the provider:

1. Loads AWS credentials from the standard chain (env vars, `~/.aws/credentials`, instance role, etc.)
2. Calls `redshift-serverless:GetCredentials` with your workgroup name
3. AWS returns a short-lived `dbUser` + `dbPassword` (valid 15–60 minutes)
4. The provider connects to Redshift using those ephemeral credentials
5. The password is never stored in Terraform state

The returned `dbUser` is derived from your IAM identity:

| IAM identity | Redshift username |
|---|---|
| `arn:aws:iam::123456789012:role/my-role` | `iamr:my-role` |
| `arn:aws:iam::123456789012:user/john` | `iam:john` |

> **Note:** The `username` field in the provider is ignored when using `temporary_credentials_serverless` — the username is always determined by the IAM identity.

---

## Limitations of IAM Temporary Credentials on Redshift Serverless

Redshift Serverless restricts certain DDL operations for IAM-authenticated sessions, even for superusers. The following provider resources are affected:

### `redshift_user` — NOT supported with IAM temporary credentials

Creating and dropping users requires the `CREATE USER` system privilege. Redshift Serverless does not grant this to IAM sessions, even when the IAM-mapped user is a superuser.

**Error you will see:**
```
pq: must be superuser or have CREATE USER system privilege to create users
```

**Workaround:** Use a second provider instance with static admin credentials for user management:

```hcl
# IAM credentials — for schemas, grants, databases
provider "redshift" {
  alias    = "iam"
  host     = var.redshift_host
  database = var.redshift_database
  type     = "serverless"
  temporary_credentials_serverless {
    workgroup_name = var.workgroup_name
    region         = var.region
  }
}

# Static admin credentials — for user management only
provider "redshift" {
  alias    = "superuser"
  host     = var.redshift_host
  database = var.redshift_database
  type     = "serverless"
  username = var.admin_username
  password = var.admin_password  # store in AWS Secrets Manager
}

# Users require superuser provider
resource "redshift_user" "appuser" {
  provider = redshift.superuser
  name     = "appuser"
  password = "StrongPassword123!"
}

# Everything else works with IAM provider
resource "redshift_schema" "myschema" {
  provider = redshift.iam
  name     = "myschema"
}

resource "redshift_grant" "schema_access" {
  provider    = redshift.iam
  user        = redshift_user.appuser.name
  schema      = redshift_schema.myschema.name
  object_type = "schema"
  privileges  = ["usage", "create"]
}
```

### One-time bootstrap

The IAM-mapped user (e.g. `iamr:my-role`) is auto-created by Redshift Serverless on first connection with minimal privileges. Before Terraform can manage schemas and grants, run this once in Query Editor v2 as the Redshift admin:

```sql
GRANT CREATE ON DATABASE "your_database" TO "iamr:my-role";
```

To find your exact IAM username:

```bash
aws sts get-caller-identity
# Then run terraform plan — the mapped username appears in outputs
```

---

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.24 (to build the provider plugin)

## Building The Provider

```sh
git clone git@github.com:Reup-Education/terraform-provider-redshift
cd terraform-provider-redshift
make build
```

## Testing Locally

Build and install the provider locally without publishing to the registry:

```sh
go build -o ~/.terraform.d/plugins/registry.terraform.io/Reup-Education/redshift/1.3.6/darwin_arm64/terraform-provider-redshift_v1.3.6
```

Then reference it normally in your Terraform config:

```hcl
terraform {
  required_providers {
    redshift = {
      source  = "Reup-Education/redshift"
      version = "1.3.6"
    }
  }
}
```

## Running Tests

**Unit tests** (no infrastructure required):

```sh
go test ./redshift/ -run TestProvider -v
```

**Acceptance tests against a provisioned cluster:**

```sh
REDSHIFT_HOST=<cluster endpoint>
REDSHIFT_USER=root
REDSHIFT_DATABASE=redshift
REDSHIFT_PASSWORD=<password>
make testacc
```

**Acceptance tests against Redshift Serverless:**

```sh
REDSHIFT_HOST=<serverless endpoint>
REDSHIFT_DATABASE=<database>
REDSHIFT_TEMPORARY_CREDENTIALS_SERVERLESS_WORKGROUP=<workgroup-name>
REDSHIFT_TEMPORARY_CREDENTIALS_SERVERLESS_REGION=us-east-1
go test ./redshift/ -run TestAccRedshiftServerlessTemporaryCredentials -v
```

If your cluster is only accessible from within a VPC, connect via a SOCKS proxy:

```sh
ALL_PROXY=socks5://user:password@host:port
NO_PROXY=127.0.0.1,localhost
```

## Documentation

Documentation is generated with [tfplugindocs](https://github.com/hashicorp/terraform-plugin-docs). Generated files are in `docs/` and should not be edited manually. They are derived from schema `Description` fields, [examples/](./examples), and [templates/](./templates).

```sh
go generate
```

## Releasing

Builds and releases are automated with GitHub Actions and [GoReleaser](https://github.com/goreleaser/goreleaser/).

1. Update `CHANGELOG.md` with the new version entry
2. Commit all changes
3. Tag and push:

```sh
git tag v1.x.x
git push origin main
git push origin v1.x.x
```

The release workflow triggers automatically on the new tag and publishes to the Terraform Registry.
