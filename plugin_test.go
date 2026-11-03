package caddy_pam

import (
	"net/http"
	"sync"
	"testing"
)

func TestIsAllowedFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		username string
		policy   string
		want     bool
	}{
		{name: "empty policy", username: "alice", policy: "", want: false},
		{name: "unknown key", username: "alice", policy: "group=admins", want: false},
		{name: "malformed rule", username: "alice", policy: "users=alice invalid", want: false},
		{name: "empty value", username: "alice", policy: "users=", want: false},
		{name: "empty list item", username: "alice", policy: "users=alice,", want: false},
		{name: "duplicate key", username: "alice", policy: "users=alice users=bob", want: false},
		{name: "explicit authenticated", username: "alice", policy: "authenticated", want: true},
		{name: "listed user", username: "alice", policy: "users=alice,bob", want: true},
		{name: "unlisted user", username: "mallory", policy: "users=alice,bob", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isAllowed(test.username, test.policy); got != test.want {
				t.Fatalf("isAllowed(%q, %q) = %t, want %t", test.username, test.policy, got, test.want)
			}
		})
	}
}

func TestCallbackURLRequiresAllowlistedOrigin(t *testing.T) {
	plugin := &PAMPlugin{
		CallbackPath:         "/callback",
		AllowedReturnOrigins: []string{"https://app.example.com"},
	}

	headers := make(http.Header)
	headers.Set("x-forwarded-proto", "https")
	headers.Set("x-forwarded-host", "app.example.com")
	if got, err := plugin.callbackURLFromHeaders(headers); err != nil || got != "https://app.example.com/callback" {
		t.Fatalf("callbackURLFromHeaders() = %q, %v", got, err)
	}

	headers.Set("x-forwarded-host", "attacker.example")
	if _, err := plugin.callbackURLFromHeaders(headers); err == nil {
		t.Fatal("callbackURLFromHeaders() accepted a non-allowlisted origin")
	}
}

func TestCallbackURLSupportsSingleLabelWildcard(t *testing.T) {
	plugin := &PAMPlugin{
		CallbackPath:         "/callback",
		AllowedReturnOrigins: []string{"https://*.example.com"},
	}

	tests := []struct {
		name   string
		scheme string
		host   string
		want   bool
	}{
		{name: "subdomain", scheme: "https", host: "app.example.com", want: true},
		{name: "case insensitive", scheme: "https", host: "APP.EXAMPLE.COM", want: true},
		{name: "apex", scheme: "https", host: "example.com", want: false},
		{name: "nested subdomain", scheme: "https", host: "app.dev.example.com", want: false},
		{name: "suffix confusion", scheme: "https", host: "app.example.com.evil", want: false},
		{name: "scheme mismatch", scheme: "http", host: "app.example.com", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("x-forwarded-proto", test.scheme)
			headers.Set("x-forwarded-host", test.host)
			_, err := plugin.callbackURLFromHeaders(headers)
			if got := err == nil; got != test.want {
				t.Fatalf("callback URL match for %q = %t, want %t", test.host, got, test.want)
			}
		})
	}
}

func TestCallbackURLWildcardMatchesConfiguredPort(t *testing.T) {
	plugin := &PAMPlugin{
		CallbackPath:         "/callback",
		AllowedReturnOrigins: []string{"https://*.example.com:8443"},
	}

	for _, test := range []struct {
		host string
		want bool
	}{
		{host: "app.example.com:8443", want: true},
		{host: "app.example.com", want: false},
	} {
		headers := make(http.Header)
		headers.Set("x-forwarded-proto", "https")
		headers.Set("x-forwarded-host", test.host)
		_, err := plugin.callbackURLFromHeaders(headers)
		if got := err == nil; got != test.want {
			t.Errorf("callback URL match for %q = %t, want %t", test.host, got, test.want)
		}
	}
}

func TestNormalizeOriginRejectsWildcardPublicSuffixes(t *testing.T) {
	for _, origin := range []string{"https://*.com", "https://*.co.uk", "https://*.github.io", "https://app.*.example.com", "https://*.*.example.com"} {
		if _, err := normalizeOrigin(origin); err == nil {
			t.Errorf("normalizeOrigin(%q) unexpectedly succeeded", origin)
		}
	}
}

func TestNormalizeOriginAllowsInternalDomains(t *testing.T) {
	for _, origin := range []string{
		"https://*.lastname",
		"https://*.foobar",
		"https://*.company.internal",
		"https://*.home.arpa",
	} {
		if _, err := normalizeOrigin(origin); err != nil {
			t.Errorf("normalizeOrigin(%q) failed: %v", origin, err)
		}
	}
}

func TestCallbackURLSupportsUnlistedPrivateTLD(t *testing.T) {
	plugin := &PAMPlugin{
		CallbackPath:         "/callback",
		AllowedReturnOrigins: []string{"https://*.lastname"},
	}
	headers := make(http.Header)
	headers.Set("x-forwarded-proto", "https")
	headers.Set("x-forwarded-host", "home.lastname")
	if got, err := plugin.callbackURLFromHeaders(headers); err != nil || got != "https://home.lastname/callback" {
		t.Fatalf("callbackURLFromHeaders() = %q, %v", got, err)
	}
}

func TestLoginFlowIsBoundAndSingleUse(t *testing.T) {
	plugin := &PAMPlugin{
		flowMu:     &sync.Mutex{},
		loginFlows: make(map[string]loginFlow),
	}
	callbackURL := "https://app.example.com/callback"
	state, err := plugin.createLoginFlow(callbackURL, "/private?tab=1")
	if err != nil {
		t.Fatal(err)
	}

	if got, ok := plugin.completeLoginFlow(state, "signed-jwt"); !ok || got != callbackURL {
		t.Fatalf("completeLoginFlow() = %q, %t", got, ok)
	}
	if _, ok := plugin.consumeLoginFlow(state, "https://other.example/callback"); ok {
		t.Fatal("consumeLoginFlow() accepted a different callback URL")
	}

	flow, ok := plugin.consumeLoginFlow(state, callbackURL)
	if !ok {
		t.Fatal("consumeLoginFlow() rejected the matching callback URL")
	}
	if flow.token != "signed-jwt" || flow.originalURI != "/private?tab=1" {
		t.Fatalf("consumed unexpected flow: %#v", flow)
	}
	if _, ok := plugin.consumeLoginFlow(state, callbackURL); ok {
		t.Fatal("consumeLoginFlow() allowed the same flow to be consumed twice")
	}
}
