# Authorization.API

A self-hosted OAuth 2.0 authorization server for your own apps. It is MIT-licensed, runs on ASP.NET Core 9, and does not require Duende, Auth0, or a cloud identity product.

Supported grants:

- Authorization code + PKCE
- Refresh token
- Client credentials
- Resource-owner JSON login (`POST /account/login/token`) for first-party apps

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- [Docker](https://docs.docker.com/get-docker/) for the local SQL Server container (no Azure SQL / RDS required)

## Quick start (Docker Compose)

This is the simplest local path: SQL Server and the API both run in containers.

```bash
docker compose up --build
```

Then open:

- API: http://localhost:8080
- Scalar docs: http://localhost:8080/scalar
- Login: http://localhost:8080/account/login

The API applies EF Core migrations and seeds demo data on startup.

### Demo credentials (local only)

| Kind | Value |
| --- | --- |
| Admin user | `admin@localhost` / `Admin123!` |
| Demo user | `demo@example.com` / `Password1!` |
| Confidential client | `demo-client` / `demo-secret` |
| Public SPA client | `demo-spa` (no secret; PKCE required) |
| Redirect URI | `http://localhost:3000/callback` |

Change these before any shared or production use.

## Alternative: Aspire AppHost

If you already use .NET Aspire, the AppHost starts a SQL Server container, waits until it is healthy, and runs the API against it:

```bash
dotnet run --project Authorization.API.AppHost
```

SQL Server data is stored in a Docker volume (`authorization-sql-data`) so it survives restarts. The local SA password defaults to `LocalDev_Sql#2026`.

## Alternative: SQL container + API on the host

```bash
docker compose up -d sqlserver
dotnet run --project Authorization.API --launch-profile http
```

`appsettings.Development.json` already points at `localhost,1433` with the same local SA password.

## Configuration

Set secrets with environment variables or user secrets, not production config files:

| Setting | Purpose |
| --- | --- |
| `ConnectionStrings__DefaultConnection` | SQL Server connection string |
| `Jwt__SecretKey` | HMAC signing key for access tokens |
| `Jwt__Issuer` / `Jwt__Audience` | Token issuer and audience |
| `EncryptionKey` | Base64 AES-256 key (32 bytes decoded) |
| `Database__MigrateOnStartup` | Apply EF migrations on boot (on in Development) |
| `Seed__Enabled` | Create demo users/clients (on in Development) |

Production should set `Database__MigrateOnStartup` and `Seed__Enabled` to `false` unless you intentionally want boot-time migration.

## Admin client APIs

Register and rotate OAuth clients without writing SQL. These endpoints require a JWT for a user in the `Administrator` role (the seeded `admin@localhost` user).

```bash
# 1. Sign in as admin
curl -s -X POST http://localhost:8080/account/login/token \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@localhost","password":"Admin123!"}'

# 2. Create a client (the plaintext secret is returned once)
curl -X POST http://localhost:8080/admin/clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"clientId":"spa","redirectUri":"http://localhost:3000/callback","allowedScopes":["openid","api"]}'
```

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/clients` | List clients (secrets never returned) |
| GET | `/admin/clients/{id}` | Get one client |
| POST | `/admin/clients` | Create client; secret is hashed at rest |
| PUT | `/admin/clients/{id}` | Update metadata and scopes |
| POST | `/admin/clients/{id}/secret` | Rotate secret |
| DELETE | `/admin/clients/{id}` | Delete client |

Client secrets are stored with ASP.NET Identity's password hasher. Existing plaintext secrets are hashed automatically on the next startup seed.

Public clients (`requireClientSecret: false`) skip the secret, require PKCE, and cannot use the client credentials grant. After login, users see a consent screen the first time a client requests scopes.

Refresh tokens rotate on every use. Presenting a previously rotated token revokes the entire token family.

## Example: authorization code + PKCE

```text
GET /authorize?response_type=code
  &client_id=demo-client
  &redirect_uri=http://localhost:3000/callback
  &scope=openid profile api
  &state=abc
  &code_challenge=...
  &code_challenge_method=S256
```

After sign-in, the browser is redirected back with `code`. Exchange it:

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-secret" \
  -d "code=..." \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=..."
```

## Project layout

- `Authorization.API` — HTTP APIs, login UI, token issuance
- `Authorization.API.AppHost` — Aspire orchestrator (SQL container + API)
- `Authorization.API.ServiceDefaults` — health checks and OpenTelemetry
- `docker-compose.yml` — local SQL Server (and optional API) without a cloud database
