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
* 🚪 Logout endpoint for switching accounts
* 📜 Structured login and authorization logs
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
    allowed_return_origins https://app.example.com
    session_lifetime 12h
    session_cookie_name __PAM_Session
    return_cookie_name __PAM_Return_URI
    callback_path /cdn-cgi/pam-callback
    logout_path /cdn-cgi/pam-logout
    return_query_param returnTo
    denied_query_param denied
    cookie_secure true
    cookie_httponly true
    cookie_samesite strict
    show_detailed_pam_result false
}
```

### Directive options

| Option             | Default  | Description                                    |
| ------------------ | -------- | ---------------------------------------------- |
| `base_url`         | required | URL users are redirected to for authentication |
| `allowed_return_origins` | required | Exact callback origins or one-label subdomain patterns |
| `session_lifetime` | `12h`    | Lifetime of authentication sessions            |
| `session_cookie_name` | `__PAM_Session` | Name of the authentication session cookie |
| `return_cookie_name` | `__PAM_Return_URI` | Name of the short-lived login-flow cookie |
| `callback_path` | `/cdn-cgi/pam-callback` | Path used for the authentication callback |
| `logout_path` | `/cdn-cgi/pam-logout` | Path used to log out |
| `return_query_param` | `returnTo` | Query parameter used to carry the opaque login-flow state |
| `denied_query_param` | `denied` | Query parameter used to indicate the denied username |
| `cookie_secure`    | `true`   | Enable the Secure cookie flag                  |
| `cookie_httponly`  | `true`   | Enable HttpOnly cookies                        |
| `cookie_samesite`  | `strict` | Cookie SameSite policy                         |
| `show_detailed_pam_result` | `false`   | Return the PAM result name (e.g. `PAM_USER_UNKNOWN`) to the client instead of a generic `authentication failed`. Enabling it allows user enumeration |

Supported SameSite values:

* `strict`
* `lax`
* `none`

`allowed_return_origins` must cover every protected site origin that uses this authentication service. Exact origins are supported, along with a leading `*.` for one subdomain label:

```caddyfile
allowed_return_origins https://app.example.com https://*.example.net
```

The wildcard matches `https://team.example.net`, but not `https://example.net` or `https://team.dev.example.net`. Scheme and port must match. Wildcards are accepted for registrable domains and for unlisted single-label private TLDs such as `https://*.lastname` or `https://*.foobar`. The reserved `https://*.home.arpa` namespace is also supported. Other known public suffixes such as `https://*.com`, `https://*.co.uk`, and `https://*.github.io` are rejected. Paths, ports-as-wildcards, and wildcards anywhere other than the complete leftmost host label are not supported.

**Security risk:** every matching subdomain becomes a trusted callback origin. Only use a wildcard when you control and protect all matching subdomains; avoid domains where users or third parties can create subdomains, and remove stale DNS records to prevent subdomain takeover. Prefer exact origins when practical.

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
4. If no valid session exists, the user is redirected to the authentication service with a short-lived opaque flow state.
   If the session is valid but the `PAM-Allow` policy rejects the user, the redirect also carries a `denied=<username>` query parameter.
5. The user submits credentials through the login page.
6. Credentials are validated through PAM.
7. The signed JWT is kept server-side; the browser returns to the allowlisted callback with the opaque state, not the JWT.
8. The callback verifies the state cookie, callback origin, and one-time flow before setting the session cookie.
9. The original request continues.

> **Note:** `caddy-pam` does not provide a built-in login page. The user-facing authentication UI is intentionally left to the operator. A minimal example login page is included in `example/index.html` and can be used as a starting point or customized for your environment. A custom page must submit the `returnTo` state with credentials, then navigate to the returned `callbackURL` with the returned `state`. Do not put the JWT in a URL. The example shows a permission warning, with a sign-out link, when the `denied` parameter is present.

Login flow state is held in process memory for five minutes. Requests in a flow must reach the same authentication-service instance; multi-instance deployments need session affinity or shared flow storage. The signing key is also process-local, so session validation already requires a consistent instance or a shared-key design.

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
        allowed_return_origins https://app.example.com
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
* Redirects to the authentication service if login is required or the user is not authorized (the latter adds `denied=<username>`)

When successful, it also adds:

```http
x-pam-user: username
```

#### Logout

The session cookie belongs to the protected site, so logout is requested on that site at `/cdn-cgi/pam-logout`. The request goes through `forward_auth`, which clears the session cookie and redirects to the login page. After signing in again the user is returned to `/`.

```html
<a href="/cdn-cgi/pam-logout">Sign out</a>
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

## Logging

The plugin logs through Caddy's logger, so entries go to stderr and from there to the systemd journal or container log driver:

| Message                | Level | Fields                                      |
| ---------------------- | ----- | ------------------------------------------- |
| `pam login succeeded`  | info  | `user`, `client_ip`                         |
| `pam login failed`     | warn  | `user`, `client_ip`, `pam_result` (description), `pam_code` (raw PAM return code) |
| `authorization denied` | warn  | `user`, `client_ip`, `policy`, `uri`        |

`client_ip` for login events honours Caddy's `trusted_proxies`. For `authorization denied` it comes from `X-Forwarded-For`.

Example fail2ban setup reading the journal (`backend = systemd`, `journalmatch = _SYSTEMD_UNIT=caddy.service`):

```ini
failregex = "msg":"pam login failed".*"client_ip":"<ADDR>"
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
