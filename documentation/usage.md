# Usage

## Table of Contents

- [loch-s3 CLI](#loch-s3-cli)
- [Cyberduck](#cyberduck)

---

## loch-s3 CLI

`loch-s3` is a command-line tool for managing users via the administration API. It is distributed alongside the `s3` server binary in releases and the Docker image.

The administration API must be enabled on the server (`S3_USERS_FILE` + `S3_ADMIN_API_KEY`).

### Configuration

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--server` | `LOCH_SERVER` | `http://localhost:8080` | Server URL |
| `--api-key` | `LOCH_ADMIN_KEY` | _(required)_ | Administration API key (Bearer token) |

Flags take precedence over environment variables. To avoid exposing the key in the process list, prefer environment variables.

```bash
export LOCH_SERVER=http://localhost:8080
export LOCH_ADMIN_KEY=my-admin-key
```

### Commands

#### List All Users

```bash
loch-s3 users list
```

Output (JSON):

```json
{
  "users": [
    {
      "user_id": "root",
      "display_name": "Root",
      "access_key_id": "EIWcQK7Dp5dub4Fy9B2m",
      "is_root": true
    },
    {
      "user_id": "alice",
      "display_name": "Alice",
      "access_key_id": "AKIAALICE00000000",
      "is_root": false
    }
  ]
}
```

The `secret_access_key` is never returned by the API.

#### Get a Specific User

```bash
loch-s3 users get alice
```

#### Create or Update a User (Manually Provided Credentials)

```bash
loch-s3 users put alice \
  --display-name "Alice" \
  --access-key AKIAALICE00000000 \
  --secret-key "AliceSecretKey40CharactersMinimum"
```

The `--access-key` and `--secret-key` flags can also be passed via the `LOCH_ACCESS_KEY` and `LOCH_SECRET_KEY` environment variables.

Returns `Created` (HTTP 201) if the user is new, `Updated` (HTTP 200) if it already existed.

#### Create a User with Auto-Generated Credentials

```bash
loch-s3 users create "Alice Dupont"
```

The `user_id` is derived from the name by slugification (lowercase, non-alphanumeric characters replaced by `-`). Credentials are randomly generated and displayed once:

```
User:       alice-dupont
Access Key: xK9mP2nQ7rL4jW8vT5sY
Secret Key: bN3hF6kD1gA9cE7iJ0mR4pU2wZ5yX8oV1qL3tY6n
```

If the user already existed, a warning is displayed and the credentials are replaced.

#### Delete a User

```bash
loch-s3 users delete alice
```

The root user cannot be deleted.

### From Docker

Both binaries (`s3` and `loch-s3`) are included in the Docker image:

```bash
docker exec <container> loch-s3 \
  --server http://localhost:8080 \
  --api-key "$S3_ADMIN_API_KEY" \
  users list
```

---

## Cyberduck

A Cyberduck connection profile is provided in the repository: `LochS3.cyberduckprofile`.

### Profile Installation

1. Download or locate the `LochS3.cyberduckprofile` file from the repository.
2. Double-click the file to install it in Cyberduck.
3. In Cyberduck, open a new connection and select the **Loch S3** protocol.

### Connection Configuration

| Field | Value |
|-------|-------|
| Protocol | Loch S3 (installed profile) |
| Server | `localhost` (or your server address) |
| Port | `8080` |
| Access Key ID | Your access key |
| Secret Access Key | Your secret key |

The profile automatically configures:
- Region: `loch-sh`
- Authentication: AWS Signature V4 (`AWS4HMACSHA256`)
- URL mode: path-style (virtual-hosted disabled)
- Default encryption algorithm: `AES256`
