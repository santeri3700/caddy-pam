package caddy_pam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/user"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/molpeDE/caddy-pam/pam"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

type PAMPlugin struct {
	echo                  *echo.Echo
	jwtKey                *ecdsa.PrivateKey
	logger                *zap.Logger
	BaseURL               string               `json:"baseURL,omitempty"`
	SessionLifetime       time.Duration        `json:"sessionLifetime,omitempty"`
	CookieHTTPOnly        bool                 `json:"cookieHttpOnly,omitempty"`
	CookieSecure          bool                 `json:"cookieSecure,omitempty"`
	CookieSameSite        http.SameSite        `json:"cookieSameSite,omitempty"`
	ShowDetailedPAMResult bool                 `json:"showDetailedPamResult,omitempty"`
	SessionCookieName     string               `json:"sessionCookieName,omitempty"`
	ReturnCookieName      string               `json:"returnCookieName,omitempty"`
	CallbackPath          string               `json:"callbackPath,omitempty"`
	LogoutPath            string               `json:"logoutPath,omitempty"`
	ReturnQueryParam      string               `json:"returnQueryParam,omitempty"`
	DeniedQueryParam      string               `json:"deniedQueryParam,omitempty"`
	AllowedReturnOrigins  []string             `json:"allowedReturnOrigins,omitempty"`
	flowMu                *sync.Mutex          `json:"-"`
	loginFlows            map[string]loginFlow `json:"-"`
}

type LoginRequest struct {
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
	State    string `form:"state" json:"state"`
}

type LoginFlowResponse struct {
	CallbackURL string `json:"callbackURL"`
	State       string `json:"state,omitempty"`
}

type loginFlow struct {
	callbackURL string
	originalURI string
	token       string
	expiresAt   time.Time
}

const FALLTHROUGH_HANDLER_KEY string = "fallthroughHandler"
const CALLBACK_PATH_DEFAULT = "/cdn-cgi/pam-callback"
const LOGOUT_PATH_DEFAULT = "/cdn-cgi/pam-logout"
const RETURN_QUERY_PARAM_DEFAULT = "returnTo"
const DENIED_QUERY_PARAM_DEFAULT = "denied"
const SESSION_COOKIE_NAME_DEFAULT = "__PAM_Session"
const RETURN_COOKIE_NAME_DEFAULT = "__PAM_Return_URI"
const SESSION_LIFETIME_DEFAULT = 60 * 60 * 12
const loginFlowLifetime = 5 * time.Minute
const maxPendingLoginFlows = 4096

func init() {
	caddy.RegisterModule(PAMPlugin{})
	httpcaddyfile.RegisterHandlerDirective("pam_auth", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m PAMPlugin
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return &m, err
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
		if len(parts) != 2 || (parts[0] != "users" && parts[0] != "groups") || parts[1] == "" {
			return false
		}

		key := parts[0]
		if _, exists := result[key]; exists {
			return false
		}

		values := strings.Split(parts[1], ",")
		for _, value := range values {
			if value == "" {
				return false
			}
		}

		result[key] = values
	}

	allowedUsers := result["users"]
	allowedGroups := result["groups"]

	if len(allowedUsers) == 0 && len(allowedGroups) == 0 {
		return false
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

// Caddy's client_ip honours trusted_proxies, unlike echo's spoofable RealIP.
func clientIP(c echo.Context) string {
	ip, _ := caddyhttp.GetVar(c.Request().Context(), caddyhttp.ClientIPVarKey).(string)
	return ip
}

func normalizeOrigin(raw string) (string, error) {
	wildcard := strings.Contains(raw, "*")
	parseValue := raw
	if wildcard {
		separator := strings.Index(raw, "://")
		if strings.Count(raw, "*") != 1 || separator < 0 || !strings.HasPrefix(raw[separator+3:], "*.") {
			return "", fmt.Errorf("invalid return origin %q", raw)
		}
		parseValue = raw[:separator+3] + "wildcard." + strings.TrimPrefix(raw[separator+3:], "*.")
	}

	u, err := url.Parse(parseValue)
	if err != nil {
		return "", fmt.Errorf("invalid return origin %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Host == "" ||
		(scheme != "http" && scheme != "https") || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#") ||
		strings.ContainsAny(u.Host, ", \t\r\n") {
		return "", fmt.Errorf("invalid return origin %q", raw)
	}

	host := strings.ToLower(u.Host)
	if wildcard {
		hostname := strings.ToLower(u.Hostname())
		suffix := strings.TrimPrefix(hostname, "wildcard.")
		if suffix == hostname {
			return "", fmt.Errorf("invalid return origin %q", raw)
		}
		registrableDomain, err := publicsuffix.EffectiveTLDPlusOne(suffix)
		if err != nil || registrableDomain != suffix {
			publicSuffix, isICANN := publicsuffix.PublicSuffix(suffix)
			// home.arpa is reserved for private home networks, not public registration.
			reservedHomeDomain := suffix == "home.arpa"
			if !reservedHomeDomain && (strings.Contains(suffix, ".") || !isValidDNSLabel(suffix) || publicSuffix != suffix || isICANN) {
				return "", fmt.Errorf("wildcard return origin must use a registrable domain or an unlisted private TLD: %q", raw)
			}
		}
		host = "*." + suffix
		if port := u.Port(); port != "" {
			host += ":" + port
		}
	}
	return scheme + "://" + host, nil
}

func isValidDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func originMatches(allowedOrigin string, candidateOrigin string) bool {
	allowed, err := normalizeOrigin(allowedOrigin)
	if err != nil {
		return false
	}
	candidate, err := normalizeOrigin(candidateOrigin)
	if err != nil {
		return false
	}
	if allowed == candidate {
		return true
	}

	allowedURL, err := url.Parse(allowed)
	if err != nil || !strings.HasPrefix(allowedURL.Hostname(), "*.") {
		return false
	}
	candidateURL, err := url.Parse(candidate)
	if err != nil || allowedURL.Scheme != candidateURL.Scheme || allowedURL.Port() != candidateURL.Port() {
		return false
	}

	suffix := strings.TrimPrefix(allowedURL.Hostname(), "*.")
	matchedPrefix, ok := strings.CutSuffix(candidateURL.Hostname(), "."+suffix)
	return ok && matchedPrefix != "" && !strings.Contains(matchedPrefix, ".")
}

func (m *PAMPlugin) callbackURLFromHeaders(headers http.Header) (string, error) {
	scheme := strings.ToLower(headers.Get("x-forwarded-proto"))
	host := headers.Get("x-forwarded-host")
	if (scheme != "http" && scheme != "https") || host == "" || strings.ContainsAny(host, "*, \t\r\n") {
		return "", errors.New("invalid forwarded callback origin")
	}

	u, err := url.Parse(scheme + "://" + host + m.CallbackPath)
	if err != nil || u.User != nil || u.Path != m.CallbackPath || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid forwarded callback URL")
	}

	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	for _, configuredOrigin := range m.AllowedReturnOrigins {
		if originMatches(configuredOrigin, origin) {
			return u.String(), nil
		}
	}
	return "", errors.New("callback origin is not allowed")
}

func parseOriginalURI(raw string) (*url.URL, error) {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return nil, errors.New("invalid forwarded request URI")
	}

	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return nil, errors.New("invalid forwarded request URI")
	}
	return u, nil
}

func (m *PAMPlugin) createLoginFlow(callbackURL string, originalURI string) (string, error) {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	now := time.Now()

	m.flowMu.Lock()
	defer m.flowMu.Unlock()

	if m.loginFlows == nil {
		m.loginFlows = make(map[string]loginFlow)
	}
	for existingState, flow := range m.loginFlows {
		if !flow.expiresAt.After(now) {
			delete(m.loginFlows, existingState)
		}
	}
	if len(m.loginFlows) >= maxPendingLoginFlows {
		return "", errors.New("too many pending login flows")
	}

	m.loginFlows[state] = loginFlow{
		callbackURL: callbackURL,
		originalURI: originalURI,
		expiresAt:   now.Add(loginFlowLifetime),
	}
	return state, nil
}

func (m *PAMPlugin) getLoginFlow(state string) (loginFlow, bool) {
	m.flowMu.Lock()
	defer m.flowMu.Unlock()

	flow, ok := m.loginFlows[state]
	if !ok {
		return loginFlow{}, false
	}
	if !flow.expiresAt.After(time.Now()) {
		delete(m.loginFlows, state)
		return loginFlow{}, false
	}
	return flow, true
}

func (m *PAMPlugin) completeLoginFlow(state string, token string) (string, bool) {
	m.flowMu.Lock()
	defer m.flowMu.Unlock()

	flow, ok := m.loginFlows[state]
	if !ok || !flow.expiresAt.After(time.Now()) || flow.token != "" {
		return "", false
	}
	flow.token = token
	m.loginFlows[state] = flow
	return flow.callbackURL, true
}

func (m *PAMPlugin) consumeLoginFlow(state string, callbackURL string) (loginFlow, bool) {
	m.flowMu.Lock()
	defer m.flowMu.Unlock()

	flow, ok := m.loginFlows[state]
	if !ok || !flow.expiresAt.After(time.Now()) || flow.token == "" || flow.callbackURL != callbackURL {
		return loginFlow{}, false
	}
	delete(m.loginFlows, state)
	return flow, true
}

func (m *PAMPlugin) loginURL(state string, deniedUser string) (string, error) {
	u, err := url.Parse(m.BaseURL)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set(m.ReturnQueryParam, state)
	if deniedUser != "" {
		query.Set(m.DeniedQueryParam, deniedUser)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
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

	m.logger = ctx.Logger()
	if m.SessionCookieName == "" {
		m.SessionCookieName = SESSION_COOKIE_NAME_DEFAULT
	}
	if m.ReturnCookieName == "" {
		m.ReturnCookieName = RETURN_COOKIE_NAME_DEFAULT
	}
	if m.CallbackPath == "" {
		m.CallbackPath = CALLBACK_PATH_DEFAULT
	}
	if m.LogoutPath == "" {
		m.LogoutPath = LOGOUT_PATH_DEFAULT
	}
	if m.ReturnQueryParam == "" {
		m.ReturnQueryParam = RETURN_QUERY_PARAM_DEFAULT
	}
	if m.DeniedQueryParam == "" {
		m.DeniedQueryParam = DENIED_QUERY_PARAM_DEFAULT
	}
	m.flowMu = &sync.Mutex{}
	m.loginFlows = make(map[string]loginFlow)

	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Recover())

	e.GET("/authenticate", func(c echo.Context) error {

		headers := c.Request().Header
		originalURI := headers.Get("x-forwarded-uri")
		orig, err := parseOriginalURI(originalURI)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid forwarded request URI")
		}

		// the session cookie lives on the protected site, so logout must be requested through it
		if orig.Path == m.LogoutPath {
			callbackURL, err := m.callbackURLFromHeaders(headers)
			if err != nil {
				return c.String(http.StatusBadRequest, "invalid callback origin")
			}
			state, err := m.createLoginFlow(callbackURL, "/")
			if err != nil {
				return c.String(http.StatusServiceUnavailable, "unable to start login flow")
			}

			c.SetCookie(m.mkCookie(m.SessionCookieName, "", -1))
			c.SetCookie(m.mkCookie(m.ReturnCookieName, state, int(loginFlowLifetime.Seconds())))
			loginURL, err := m.loginURL(state, "")
			if err != nil {
				return err
			}
			return c.Redirect(http.StatusTemporaryRedirect, loginURL)
		}

		deniedUser := ""

		if cookie, err := c.Cookie(m.SessionCookieName); cookie != nil && err == nil {
			if username, err := m.confirmJwt(cookie.Value); err == nil {
				if isAllowed(username, headers.Get("PAM-Allow")) {
					c.Response().Header().Add("x-pam-user", username)
					return c.NoContent(http.StatusOK)
				}
				deniedUser = username
			}
		}

		if orig.Path == m.CallbackPath {
			callbackURL, err := m.callbackURLFromHeaders(headers)
			if err != nil {
				return c.String(http.StatusBadRequest, "invalid callback origin")
			}
			state := orig.Query().Get("state")
			cookie, err := c.Cookie(m.ReturnCookieName)
			if state == "" || err != nil || cookie.Value != state {
				return c.String(http.StatusBadRequest, "invalid login state")
			}

			flow, ok := m.consumeLoginFlow(state, callbackURL)
			if !ok {
				return c.String(http.StatusBadRequest, "invalid or expired login flow")
			}
			if _, err := m.confirmJwt(flow.token); err != nil {
				return c.String(http.StatusBadRequest, "invalid login token")
			}

			c.SetCookie(m.mkCookie(m.ReturnCookieName, "", -1))
			c.SetCookie(m.mkCookie(m.SessionCookieName, flow.token, int(m.SessionLifetime.Seconds())))
			return c.Redirect(http.StatusTemporaryRedirect, flow.originalURI)
		}

		callbackURL, err := m.callbackURLFromHeaders(headers)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid callback origin")
		}
		state, err := m.createLoginFlow(callbackURL, originalURI)
		if err != nil {
			return c.String(http.StatusServiceUnavailable, "unable to start login flow")
		}
		c.SetCookie(m.mkCookie(m.ReturnCookieName, state, int(loginFlowLifetime.Seconds())))

		loginURL, err := m.loginURL(state, deniedUser)
		if err != nil {
			return err
		}
		if deniedUser != "" {
			m.logger.Warn("authorization denied", zap.String("user", deniedUser), zap.String("client_ip", headers.Get("X-Forwarded-For")), zap.String("policy", headers.Get("PAM-Allow")), zap.String("uri", headers.Get("x-forwarded-uri")))
		}

		return c.Redirect(http.StatusTemporaryRedirect, loginURL)
	})

	e.GET("/login-flow", func(c echo.Context) error {
		state := c.QueryParam("state")
		flow, ok := m.getLoginFlow(state)
		if !ok {
			return c.String(http.StatusBadRequest, "invalid or expired login flow")
		}
		return c.JSON(http.StatusOK, LoginFlowResponse{CallbackURL: flow.callbackURL})
	})

	e.POST("/login", func(c echo.Context) error {
		req := &LoginRequest{}

		if err := c.Bind(req); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		if req.Username == "" || req.Password == "" {
			return c.String(http.StatusBadRequest, "missing parameter")
		}
		flow, ok := m.getLoginFlow(req.State)
		if req.State == "" || !ok || flow.token != "" {
			return c.String(http.StatusBadRequest, "invalid or expired login flow")
		}

		ok, err := pam.Authenticate(req.Username, req.Password)

		ip := clientIP(c)

		if ok {
			m.logger.Info("pam login succeeded", zap.String("user", req.Username), zap.String("client_ip", ip))

			token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
				"user": req.Username,
				"exp":  jwt.NewNumericDate(time.Now().Add(m.SessionLifetime)),
			}).SignedString(m.jwtKey)

			if err != nil {
				return err
			}

			callbackURL, ok := m.completeLoginFlow(req.State, token)
			if !ok {
				return c.String(http.StatusBadRequest, "invalid or expired login flow")
			}
			return c.JSON(http.StatusOK, LoginFlowResponse{CallbackURL: callbackURL, State: req.State})
		} else {
			pamCode := -1
			if pe, ok := err.(*pam.Error); ok {
				pamCode = pe.Code
			}
			m.logger.Warn("pam login failed", zap.String("user", req.Username), zap.String("client_ip", ip), zap.String("pam_result", err.Error()), zap.Int("pam_code", pamCode))
			if m.ShowDetailedPAMResult {
				return c.String(http.StatusUnauthorized, err.Error())
			}
			return c.String(http.StatusUnauthorized, "Authentication failure")
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
	if len(m.AllowedReturnOrigins) == 0 {
		return fmt.Errorf("at least one allowed_return_origins entry is required")
	}
	for _, origin := range m.AllowedReturnOrigins {
		if _, err := normalizeOrigin(origin); err != nil {
			return err
		}
	}
	if !strings.HasPrefix(m.CallbackPath, "/") || strings.HasPrefix(m.CallbackPath, "//") || strings.ContainsAny(m.CallbackPath, "?#\\") {
		return fmt.Errorf("callback_path must be an absolute path without query or fragment")
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
	m.ShowDetailedPAMResult = false
	m.SessionCookieName = SESSION_COOKIE_NAME_DEFAULT
	m.ReturnCookieName = RETURN_COOKIE_NAME_DEFAULT
	m.CallbackPath = CALLBACK_PATH_DEFAULT
	m.LogoutPath = LOGOUT_PATH_DEFAULT
	m.ReturnQueryParam = RETURN_QUERY_PARAM_DEFAULT
	m.DeniedQueryParam = DENIED_QUERY_PARAM_DEFAULT

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

		case "allowed_return_origins":
			if !d.NextArg() {
				return d.ArgErr()
			}
			for {
				m.AllowedReturnOrigins = append(m.AllowedReturnOrigins, d.Val())
				if !d.NextArg() {
					break
				}
			}

		case "session_cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.SessionCookieName = d.Val()

		case "return_cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ReturnCookieName = d.Val()

		case "callback_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CallbackPath = d.Val()

		case "logout_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.LogoutPath = d.Val()

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

		case "show_detailed_pam_result":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ShowDetailedPAMResult = d.Val() == "true"

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

		case "return_query_param":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if strings.ContainsAny(d.Val(), "?&") {
				return d.Errf("return_query_param must not contain ? or &")
			}
			m.ReturnQueryParam = d.Val()

		case "denied_query_param":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if strings.ContainsAny(d.Val(), "?&") {
				return d.Errf("denied_query_param must not contain ? or &")
			}
			m.DeniedQueryParam = d.Val()

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
