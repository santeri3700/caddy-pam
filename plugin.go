package caddy_pam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/user"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/molpeDE/caddy-pam/pam"
)

type PAMPlugin struct {
	echo            *echo.Echo
	jwtKey          *ecdsa.PrivateKey
	BaseURL         string        `json:"baseURL,omitempty"`
	SessionLifetime time.Duration `json:"sessionLifetime,omitempty"`
	CookieHTTPOnly  bool          `json:"cookieHttpOnly,omitempty"`
	CookieSecure    bool          `json:"cookieSecure,omitempty"`
	CookieSameSite  http.SameSite `json:"cookieSameSite,omitempty"`
}

type LoginRequest struct {
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
}

const FALLTHROUGH_HANDLER_KEY string = "fallthroughHandler"
const PAM_SESSION = "__PAM_Session"
const PAM_RETURN = "__PAM_Return_URI"
const CALLBACK_PATH = "/cdn-cgi/pam-callback"
const SESSION_LIFETIME_DEFAULT = 60 * 60 * 12

func init() {
	caddy.RegisterModule(PAMPlugin{})
	httpcaddyfile.RegisterHandlerDirective("pam_auth", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m PAMPlugin
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return m, err
	})
	httpcaddyfile.RegisterDirectiveOrder("pam_auth", httpcaddyfile.Before, "respond")
}

func (PAMPlugin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.pam_auth",
		New: func() caddy.Module { return new(PAMPlugin) },
	}
}

func Intersect[T comparable](a, b []T) []T {
	set := make(map[T]struct{}, len(a))

	for _, v := range a {
		set[v] = struct{}{}
	}

	result := make([]T, 0)

	for _, v := range b {
		if _, ok := set[v]; ok {
			result = append(result, v)
			delete(set, v)
		}
	}

	return result
}

func getUserGroups(username string) ([]string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}

	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(gids))

	for _, gid := range gids {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			continue // optionally return the error instead
		}

		groups = append(groups, g.Name)
	}

	return groups, nil
}

func isAllowed(username string, policy string) bool {

	if policy == "authenticated" { // allow any authenticated user
		return true
	}

	result := make(map[string][]string)

	for item := range strings.FieldsSeq(policy) {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		values := strings.Split(parts[1], ",")

		result[key] = values
	}

	allowedUsers := result["users"]
	allowedGroups := result["groups"]

	if len(allowedUsers) == 0 && len(allowedGroups) == 0 {
		return true
	}

	if slices.Contains(allowedUsers, username) {
		return true
	}

	if len(allowedGroups) == 0 {
		return false
	}

	groups, err := getUserGroups(username)
	return err == nil && len(Intersect(allowedGroups, groups)) > 0
}

func (m *PAMPlugin) mkCookie(name string, value string, lifetime int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   lifetime,
		Path:     "/",
		HttpOnly: m.CookieHTTPOnly,
		SameSite: m.CookieSameSite,
		Secure:   m.CookieSecure,
	}
}

func (m *PAMPlugin) Provision(ctx caddy.Context) error {

	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Recover())

	e.GET("/authenticate", func(c echo.Context) error {

		headers := c.Request().Header

		// authenticate here

		if cookie, err := c.Cookie(PAM_SESSION); cookie != nil && err == nil {
			if username, err := m.confirmJwt(cookie.Value); err == nil && isAllowed(username, headers.Get("PAM-Allow")) {
				c.Response().Header().Add("x-pam-user", username)
				return c.NoContent(http.StatusOK)
			}
		}

		// reconstruct original request uri
		orig, _ := url.Parse(fmt.Sprintf("%s://%s%s",
			headers.Get("x-forwarded-proto"),
			headers.Get("x-forwarded-host"),
			headers.Get("x-forwarded-uri"),
		))

		// if this is the login callback set the session cookie to the callback value and restore orignal uri
		if orig.Path == CALLBACK_PATH && orig.Query().Get("token") != "" {
			if cookie, err := c.Cookie(PAM_RETURN); err == nil && cookie != nil {
				to := cookie.Value
				c.SetCookie(m.mkCookie(PAM_RETURN, "", -1))
				c.SetCookie(m.mkCookie(PAM_SESSION, orig.Query().Get("token"), int(m.SessionLifetime.Seconds())))
				return c.Redirect(http.StatusTemporaryRedirect, to)
			}
		}

		// else store the original uri in a cookie and redirect to the sso service
		c.SetCookie(m.mkCookie(PAM_RETURN, headers.Get("x-forwarded-uri"), 300))
		returnTo := fmt.Sprintf("%s://%s%s", headers.Get("x-forwarded-proto"), headers.Get("x-forwarded-host"), CALLBACK_PATH)

		redirUrl, _ := url.Parse(m.BaseURL)
		q := redirUrl.Query()
		orig.RawQuery = ""
		q.Add("returnTo", returnTo)
		redirUrl.RawQuery = q.Encode()

		return c.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
	})

	e.POST("/login", func(c echo.Context) error {
		req := &LoginRequest{}

		if err := c.Bind(req); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		if req.Username == "" || req.Password == "" {
			return c.String(http.StatusBadRequest, "missing parameter")
		}

		ok, err := pam.Authenticate(req.Username, req.Password)

		if ok {

			token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
				"user": req.Username,
				"exp":  jwt.NewNumericDate(time.Now().Add(m.SessionLifetime)),
			}).SignedString(m.jwtKey)

			if err != nil {
				return err
			}

			return c.String(http.StatusOK, token)
		} else {
			return c.String(http.StatusUnauthorized, err.Error())
		}
	})

	e.RouteNotFound("/*", func(c echo.Context) error {
		c.Request().Context().Value(FALLTHROUGH_HANDLER_KEY).(func())()
		return nil
	})

	m.echo = e
	m.jwtKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	return nil
}

func (m *PAMPlugin) confirmJwt(token string) (string, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return &m.jwtKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))

	if err != nil {
		return "", err
	}

	if !parsedToken.Valid {
		return "", errors.New("invalid token")
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		return claims["user"].(string), nil
	}

	return "", nil
}

func (m *PAMPlugin) Validate() error {

	if m.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}

	return nil
}

func (m PAMPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var err error = nil
	fallthroughFunc := func() { err = next.ServeHTTP(w, r) }
	m.echo.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), FALLTHROUGH_HANDLER_KEY, fallthroughFunc)))
	return err
}

func (m *PAMPlugin) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	m.SessionLifetime = SESSION_LIFETIME_DEFAULT * time.Second
	m.CookieHTTPOnly = true
	m.CookieSecure = true
	m.CookieSameSite = http.SameSiteStrictMode

	d.Next()

	if !d.NextBlock(0) {
		return d.ArgErr()
	}

	for {

		switch d.Val() {
		case "base_url":
			if !d.NextArg() {
				return d.ArgErr()
			}

			m.BaseURL = d.Val()

		case "session_lifetime":
			if !d.NextArg() {
				return d.ArgErr()
			}

			if dur, err := caddy.ParseDuration(d.Val()); err == nil {
				m.SessionLifetime = dur
			} else {
				return err
			}

		case "cookie_secure":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CookieSecure = d.Val() == "true"

		case "cookie_httponly":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CookieHTTPOnly = d.Val() == "true"

		case "cookie_samesite":
			if !d.NextArg() {
				return d.ArgErr()
			}
			switch d.Val() {
			case "strict":
				m.CookieSameSite = http.SameSiteStrictMode
			case "lax":
				m.CookieSameSite = http.SameSiteLaxMode
			case "none":
				m.CookieSameSite = http.SameSiteNoneMode
			default:
				m.CookieSameSite = http.SameSiteDefaultMode
			}

		default:
			return d.Errf("unknown subdirective %q", d.Val())
		}

		if !d.NextBlock(0) {
			break
		}
	}

	return nil
}

var (
	_ caddy.Provisioner           = (*PAMPlugin)(nil)
	_ caddy.Validator             = (*PAMPlugin)(nil)
	_ caddyhttp.MiddlewareHandler = (*PAMPlugin)(nil)
	_ caddyfile.Unmarshaler       = (*PAMPlugin)(nil)
)
