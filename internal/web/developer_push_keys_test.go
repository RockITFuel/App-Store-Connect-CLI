package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func pushKeyTestP8(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestDeveloperPushKeyCreateSendsEnvironmentAndDownloads(t *testing.T) {
	for _, tc := range []struct {
		env  PushKeyEnvironment
		want string
	}{
		{PushKeyEnvironmentSandbox, "development"},
		{PushKeyEnvironmentProduction, "production"},
		{PushKeyEnvironmentBoth, "all"},
	} {
		t.Run(string(tc.env), func(t *testing.T) {
			p8 := pushKeyTestP8(t)
			client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case developerPortalTeamsPath:
					return developerPortalTestResponse(200, developerPortalTeamsFixture(), http.Header{"csrf": {"team"}, "csrf_ts": {"team-ts"}}), nil
				case developerPortalLegacyPath + "/account/auth/key/list":
					return developerPortalTestResponse(200, `{"resultCode":0,"keys":[]}`, http.Header{"csrf": {"key"}, "csrf_ts": {"key-ts"}}), nil
				case developerPortalLegacyPath + "/account/auth/key/v2/create":
					var payload struct {
						TeamID   string `json:"teamId"`
						Name     string `json:"name"`
						Services []struct {
							IsNew       bool            `json:"isNew"`
							ID          string          `json:"serviceId"`
							Identifiers json.RawMessage `json:"identifiers"`
							Environment string          `json:"environment"`
							Scope       string          `json:"scope"`
						} `json:"serviceConfigurationsRequests"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if r.Header.Get("csrf") != "key" || payload.TeamID != "TEAM123456" || payload.Name != "Push" || len(payload.Services) != 1 {
						t.Fatalf("wrong create payload %+v", payload)
					}
					service := payload.Services[0]
					if service.ID != pushKeyService || !service.IsNew || string(service.Identifiers) != "{}" || service.Environment != tc.want || service.Scope != "team" {
						t.Fatalf("wrong APNs service request %+v", service)
					}
					return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"PUSH123","keyName":"Push","canDownload":true}]}`, nil), nil
				case developerPortalLegacyPath + "/account/auth/key/get":
					return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"PUSH123","keyName":"Push","canDownload":true,"services":[{"id":"U27F4V844T","configurations":[]}]}]}`, nil), nil
				case developerPortalLegacyPath + "/account/auth/key/download":
					if r.Method != http.MethodGet || r.URL.Query().Get("keyId") != "PUSH123" || r.URL.Query().Get("teamId") != "TEAM123456" {
						t.Fatal("wrong download request")
					}
					return developerPortalTestResponse(200, p8, nil), nil
				default:
					t.Fatalf("unexpected %s", r.URL)
					return nil, nil
				}
			})
			created, err := client.CreateDeveloperPushKey(context.Background(), "Push", tc.env)
			if err != nil {
				t.Fatal(err)
			}
			downloaded, err := client.DownloadDeveloperPushKey(context.Background(), created.KeyID)
			if err != nil {
				t.Fatal(err)
			}
			if string(downloaded) != p8 {
				t.Fatal("wrong P8")
			}
		})
	}
}

func TestParsePushKeyEnvironment(t *testing.T) {
	for _, value := range []string{"sandbox", "Production", " both "} {
		if _, err := ParsePushKeyEnvironment(value); err != nil {
			t.Fatalf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"", "all", "development"} {
		if _, err := ParsePushKeyEnvironment(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestDeveloperPushKeyListKeepsOnlyAPNsKeys(t *testing.T) {
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case developerPortalTeamsPath:
			return developerPortalTestResponse(200, developerPortalTeamsFixture(), http.Header{"csrf": {"team"}, "csrf_ts": {"team-ts"}}), nil
		case developerPortalLegacyPath + "/account/auth/key/list":
			return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"PUSH1","keyName":"Push","canDownload":false,"services":[{"id":"U27F4V844T"}]},{"keyId":"SIWA1","keyName":"Siwa","services":[{"id":"APPLE_ID_AUTH_KEY_CONFIGURATION"}]},{"keyId":"BARE1","keyName":"Bare"}]}`, nil), nil
		case developerPortalLegacyPath + "/account/auth/key/get":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("keyId") != "BARE1" {
				t.Fatalf("read back a key that already listed its services: %s", body)
			}
			return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"BARE1","keyName":"Bare","canDownload":true,"services":[{"id":"U27F4V844T"}]}]}`, nil), nil
		default:
			t.Fatalf("unexpected %s", r.URL)
			return nil, nil
		}
	})
	keys, err := client.ListDeveloperPushKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KeyID != "PUSH1" || keys[1].KeyID != "BARE1" {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestDeveloperPushKeyRevoke(t *testing.T) {
	revoked := false
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case developerPortalTeamsPath:
			return developerPortalTestResponse(200, developerPortalTeamsFixture(), http.Header{"csrf": {"team"}, "csrf_ts": {"team-ts"}}), nil
		case developerPortalLegacyPath + "/account/auth/key/list":
			return developerPortalTestResponse(200, `{"resultCode":0,"keys":[]}`, http.Header{"csrf": {"key"}, "csrf_ts": {"key-ts"}}), nil
		case developerPortalLegacyPath + "/account/auth/key/get":
			return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"PUSH123","services":[{"id":"U27F4V844T"}]}]}`, nil), nil
		case developerPortalLegacyPath + "/account/auth/key/revoke":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if r.Method != http.MethodPost || r.Header.Get("csrf") != "key" || form.Get("teamId") != "TEAM123456" || form.Get("keyId") != "PUSH123" {
				t.Fatalf("wrong revoke request %s %s csrf=%q", r.Method, body, r.Header.Get("csrf"))
			}
			revoked = true
			return developerPortalTestResponse(200, `{"resultCode":0}`, nil), nil
		default:
			t.Fatalf("unexpected %s", r.URL)
			return nil, nil
		}
	})
	if err := client.RevokeDeveloperPushKey(context.Background(), "PUSH123"); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("revoke was not sent")
	}
}

func TestDeveloperPushKeyRefusesOtherServicesAndDuplicateNames(t *testing.T) {
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case developerPortalTeamsPath:
			return developerPortalTestResponse(200, developerPortalTeamsFixture(), http.Header{"csrf": {"team"}, "csrf_ts": {"team-ts"}}), nil
		case developerPortalLegacyPath + "/account/auth/key/list":
			return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"SIWA1","keyName":"Push","canDownload":true}]}`, http.Header{"csrf": {"key"}, "csrf_ts": {"key-ts"}}), nil
		case developerPortalLegacyPath + "/account/auth/key/get":
			return developerPortalTestResponse(200, `{"resultCode":0,"keys":[{"keyId":"SIWA1","keyName":"Push","canDownload":true,"services":[{"id":"APPLE_ID_AUTH_KEY_CONFIGURATION","configurations":[]}]}]}`, nil), nil
		default:
			t.Fatalf("unexpected %s", r.URL)
			return nil, nil
		}
	})
	if _, err := client.CreateDeveloperPushKey(context.Background(), "Push", PushKeyEnvironmentBoth); err == nil || !strings.Contains(err.Error(), "already has this name") {
		t.Fatalf("expected duplicate-name refusal, got %v", err)
	}
	if _, err := client.DownloadDeveloperPushKey(context.Background(), "SIWA1"); err == nil || !strings.Contains(err.Error(), "is not an APNs key") {
		t.Fatalf("expected download service refusal, got %v", err)
	}
	if err := client.RevokeDeveloperPushKey(context.Background(), "SIWA1"); err == nil || !strings.Contains(err.Error(), "is not an APNs key") {
		t.Fatalf("expected revoke service refusal, got %v", err)
	}
}
