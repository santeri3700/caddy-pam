# caddy-pam

[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![Caddy](https://img.shields.io/badge/Caddy-2.x-1f88c9?logo=caddy)](https://caddyserver.com/)

A PAM authentication plugin for [Caddy](https://caddyserver.com/) that provides system-user authentication, JWT-based sessions, and access control through Caddy's `forward_auth` middleware.

`caddy-pam` allows Caddy to authenticate users against the host operating system's PAM stack and protect HTTP resources without requiring an external identity provider.

## Features

* 🔐 Authenticate users through Linux PAM
* 👤 Restrict access by username and Unix group membership
* 🍪 Secure session cookies with configurable lifetime
* 🔑 Signed JWT session tokens
* 🔌 Native Caddy `forward_auth` integration
* 🐧 Uses existing system authentication configuration

## Requirements

### Linux PAM

The Caddy process must have permission to authenticate users.

On most Linux distributions this requires access to the shadow password database. Add the user running Caddy to the `shadow` group:

```bash
sudo usermod -aG shadow caddy
```

Restart Caddy after changing group membership.

The exact requirements depend on your PAM configuration and distribution.

### CGO

This plugin requires CGO because the Linux PAM API is exposed through C libraries.

CGO must be enabled when building Caddy:

```bash
CGO_ENABLED=1
```

Example:

```bash
CGO_ENABLED=1 xcaddy build \
  --with github.com/molpeDE/caddy-pam
```

## Installation

Install `xcaddy`:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Build Caddy with the plugin:

```bash
CGO_ENABLED=1 xcaddy build \
  --with github.com/molpeDE/caddy-pam
```

Verify the plugin is installed:

```bash
caddy list-modules | grep pam
```

Expected output:

```text
http.handlers.pam_auth
```

## Configuration

Add the `pam_auth` directive to your Caddyfile:

```caddyfile
pam_auth {
    base_url https://auth.example.com
    session_lifetime 12h
    cookie_secure true
    cookie_httponly true
    cookie_samesite strict
}
```

### Directive options

| Option             | Default  | Description                                    |
| ------------------ | -------- | ---------------------------------------------- |
| `base_url`         | required | URL users are redirected to for authentication |
| `session_lifetime` | `12h`    | Lifetime of authentication sessions            |
| `cookie_secure`    | `true`   | Enable the Secure cookie flag                  |
| `cookie_httponly`  | `true`   | Enable HttpOnly cookies                        |
| `cookie_samesite`  | `strict` | Cookie SameSite policy                         |

Supported SameSite values:

* `strict`
* `lax`
* `none`

## Authentication flow

```text
User
 |
 v
Protected website
 |
 | forward_auth
 v
PAM authentication service
 |
 | PAM login
 v
Operating system users
```

The flow:

1. A user requests a protected resource.
2. Caddy calls `/authenticate`.
3. The plugin checks the session cookie.
4. If no valid session exists, the user is redirected to the authentication service.
5. The user submits credentials through the login page.
6. Credentials are validated through PAM.
7. A signed JWT session is issued.
8. The original request continues.

> **Note:** `caddy-pam` does not provide a built-in login page. The user-facing authentication UI is intentionally left to the operator. A minimal example login page is included in `examples/index.html` and can be used as a starting point or customized for your environment.

## Access control

The `PAM-Allow` header controls who is allowed access and **should be considered a required security configuration when using `forward_auth`**.

The header must be set by the trusted Caddy proxy:

```caddyfile
header_up PAM-Allow "groups=developers"
```

Do **not** leave this header unconfigured! If clients can send their own `PAM-Allow` header to the authentication service, they could modify the access policy and potentially grant themselves access by requesting a less restrictive policy.

For this reason, the authentication service should only be reachable through a trusted Caddy instance that overwrites `PAM-Allow`.

Supported policies:

### Allow all authenticated users

```caddyfile
header_up PAM-Allow "authenticated"
```

### Allow specific users

```caddyfile
header_up PAM-Allow "users=alice,bob"
```

### Allow Unix groups

```caddyfile
header_up PAM-Allow "groups=admins"
```

### Combine users and groups

```caddyfile
header_up PAM-Allow "users=alice groups=admins"
```

Group membership is resolved using the host operating system's user database.

## Example deployment

A common setup is to run a dedicated authentication endpoint and protect one or more services with `forward_auth`.

Example:

```caddyfile
auth.example.com {
    pam_auth {
        base_url https://auth.example.com
        session_lifetime 1h
    }

    root * /var/www/auth
    file_server
}

app.example.com {
    forward_auth https://auth.example.com {
        uri /authenticate
        header_up PAM-Allow "groups=developers"
    }

    reverse_proxy localhost:8080
}
```

In this example:

* `auth.example.com` provides the PAM authentication service.
* `app.example.com` is protected using Caddy's `forward_auth`.
* Only users in the `developers` group can access the application.
* TLS certificates are automatically managed by Caddy.
* The login page is served separately and can be customized. An example implementation is available in `examples/index.html`.

## Endpoints

The plugin provides:

### `GET /authenticate`

Used by `forward_auth`.

Returns:

* `200 OK` if the session is valid
* Redirects to the authentication service if login is required

When successful, it also adds:

```http
x-pam-user: username
```

### `POST /login`

Authenticates credentials against PAM.

Request:

```json
{
  "username": "alice",
  "password": "password"
}
```

Response:

```text
<signed JWT token>
```

## Security notes

* Always use HTTPS in production.
* Keep `cookie_secure` enabled when using TLS.
* The JWT signing key is generated at startup. Restarting Caddy invalidates existing sessions.
* PAM configuration controls available authentication methods and policies.

## Troubleshooting

### Authentication always fails

Check that the Caddy user can access PAM authentication:

```bash
id caddy
```

Verify it has the required group membership to shadow:

```text
uid=999(caddy) gid=997(caddy) groups=997(caddy),33(www-data),42(shadow)
```

### Plugin build fails

Make sure CGO is enabled:

```bash
CGO_ENABLED=1
```

and that your system has PAM development headers installed.

On Debian/Ubuntu:

```bash
sudo apt install libpam0g-dev
```

## License

See the repository license for details.
