package web

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

func stubPushKeySession(t *testing.T) {
	t.Helper()
	originalResolve, originalClient, originalPersist := resolveSessionFn, newWebClientFn, persistWebSessionFn
	originalList, originalCreate, originalDownload, originalRevoke := listDeveloperPushKeysFn, createDeveloperPushKeyFn, downloadDeveloperPushKeyFn, revokeDeveloperPushKeyFn
	t.Cleanup(func() {
		resolveSessionFn, newWebClientFn, persistWebSessionFn = originalResolve, originalClient, originalPersist
		listDeveloperPushKeysFn, createDeveloperPushKeyFn, downloadDeveloperPushKeyFn, revokeDeveloperPushKeyFn = originalList, originalCreate, originalDownload, originalRevoke
	})
	resolveSessionFn = func(context.Context, string, string, string) (*webcore.AuthSession, string, error) {
		return &webcore.AuthSession{}, "cache", nil
	}
	newWebClientFn = func(*webcore.AuthSession) *webcore.Client { return &webcore.Client{} }
	persistWebSessionFn = func(*webcore.AuthSession) error { return nil }
}

func pushKeysSubcommand(d *shared.Deps, name string) *ffcli.Command {
	for _, command := range newWebPushKeysCommand(d).Subcommands {
		if command.Name == name {
			return command
		}
	}
	return nil
}

func TestWebPushKeysCreateSavesPrivateFileWithEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private P8 publication is unsupported on Windows")
	}
	stubPushKeySession(t)
	var gotName string
	var gotEnv webcore.PushKeyEnvironment
	createDeveloperPushKeyFn = func(_ context.Context, _ *webcore.Client, name string, env webcore.PushKeyEnvironment) (*webcore.DeveloperSignInKey, error) {
		gotName, gotEnv = name, env
		return &webcore.DeveloperSignInKey{KeyID: "PUSH123"}, nil
	}
	downloadDeveloperPushKeyFn = func(_ context.Context, _ *webcore.Client, keyID string) ([]byte, error) {
		if keyID != "PUSH123" {
			t.Fatalf("downloaded %s", keyID)
		}
		return []byte("PRIVATE-TEST-MATERIAL"), nil
	}
	directory := t.TempDir()
	d, depsStdout, depsStderr := newWebTestDeps()
	command := pushKeysSubcommand(d, "create")
	if err := command.FlagSet.Parse([]string{"--name", "Push", "--environment", "production", "--output-dir", directory, "--confirm", "--output", "json"}); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := runWithWebTestDeps(depsStdout, depsStderr, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	})
	if gotName != "Push" || gotEnv != webcore.PushKeyEnvironmentProduction {
		t.Fatalf("create got name=%q env=%q", gotName, gotEnv)
	}
	if strings.Contains(stdout+stderr, "PRIVATE-TEST-MATERIAL") {
		t.Fatal("private key leaked")
	}
	var receipt struct {
		KeyID       string `json:"keyId"`
		Environment string `json:"environment"`
		P8Path      string `json:"p8Path"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.KeyID != "PUSH123" || receipt.Environment != "production" || receipt.P8Path != filepath.Join(directory, "AuthKey_PUSH123.p8") {
		t.Fatalf("wrong receipt %+v", receipt)
	}
	info, err := os.Stat(receipt.P8Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("P8 is not private")
	}
	saved, err := os.ReadFile(receipt.P8Path)
	if err != nil || string(saved) != "PRIVATE-TEST-MATERIAL" {
		t.Fatal("P8 not saved")
	}
}

func TestWebPushKeysCreateRejectsUnknownEnvironmentBeforeSession(t *testing.T) {
	stubPushKeySession(t)
	resolveSessionFn = func(context.Context, string, string, string) (*webcore.AuthSession, string, error) {
		t.Fatal("resolved a session for an invalid environment")
		return nil, "", nil
	}
	d, depsStdout, depsStderr := newWebTestDeps()
	command := pushKeysSubcommand(d, "create")
	if err := command.FlagSet.Parse([]string{"--name", "Push", "--environment", "all", "--output-dir", t.TempDir(), "--confirm"}); err != nil {
		t.Fatal(err)
	}
	_, stderr := runWithWebTestDeps(depsStdout, depsStderr, func() {
		if err := command.Exec(context.Background(), nil); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("expected usage error, got %v", err)
		}
	})
	if !strings.Contains(stderr, "--environment must be sandbox, production or both") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestWebPushKeysListPrintsAPNsKeys(t *testing.T) {
	stubPushKeySession(t)
	listDeveloperPushKeysFn = func(context.Context, *webcore.Client) ([]webcore.DeveloperSignInKey, error) {
		return []webcore.DeveloperSignInKey{{KeyID: "PUSH1", KeyName: "Push", CanDownload: true}}, nil
	}
	d, depsStdout, depsStderr := newWebTestDeps()
	command := pushKeysSubcommand(d, "list")
	if err := command.FlagSet.Parse([]string{"--output", "json"}); err != nil {
		t.Fatal(err)
	}
	stdout, _ := runWithWebTestDeps(depsStdout, depsStderr, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	})
	want := `{"teamId":"","keys":[{"keyId":"PUSH1","name":"Push","canDownload":true}]}`
	if got := strings.TrimSpace(stdout); got != want {
		t.Fatalf("stdout = %s, want %s", got, want)
	}
}

func TestWebPushKeysRevokeRequiresConfirmThenRevokes(t *testing.T) {
	stubPushKeySession(t)
	revoked := ""
	revokeDeveloperPushKeyFn = func(_ context.Context, _ *webcore.Client, keyID string) error {
		revoked = keyID
		return nil
	}

	d, depsStdout, depsStderr := newWebTestDeps()
	command := pushKeysSubcommand(d, "revoke")
	if err := command.FlagSet.Parse([]string{"--key-id", "PUSH1"}); err != nil {
		t.Fatal(err)
	}
	_, stderr := runWithWebTestDeps(depsStdout, depsStderr, func() {
		if err := command.Exec(context.Background(), nil); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("expected usage error, got %v", err)
		}
	})
	if revoked != "" || !strings.Contains(stderr, "--confirm is required") {
		t.Fatalf("revoked %q without --confirm; stderr %q", revoked, stderr)
	}

	d, depsStdout, depsStderr = newWebTestDeps()
	command = pushKeysSubcommand(d, "revoke")
	if err := command.FlagSet.Parse([]string{"--key-id", "PUSH1", "--confirm", "--output", "json"}); err != nil {
		t.Fatal(err)
	}
	stdout, _ := runWithWebTestDeps(depsStdout, depsStderr, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	})
	if revoked != "PUSH1" || !strings.Contains(stdout, `"revoked":true`) {
		t.Fatalf("revoked %q, stdout %s", revoked, stdout)
	}
}

func TestWebProvidersListMarksCurrentProvider(t *testing.T) {
	stubPushKeySession(t)
	originalList := listSessionProvidersFn
	t.Cleanup(func() { listSessionProvidersFn = originalList })
	listSessionProvidersFn = func(context.Context, *webcore.AuthSession) ([]webcore.SessionProvider, error) {
		return []webcore.SessionProvider{
			{ProviderID: 1, PublicProviderID: "AAAA", Name: "One", Current: true},
			{ProviderID: 2, PublicProviderID: "BBBB", Name: "Two"},
		}, nil
	}
	d, depsStdout, depsStderr := newWebTestDeps()
	command := newWebProvidersListCommand(d)
	if err := command.FlagSet.Parse([]string{"--output", "json"}); err != nil {
		t.Fatal(err)
	}
	stdout, _ := runWithWebTestDeps(depsStdout, depsStderr, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	})
	want := `{"providers":[{"providerId":1,"publicProviderId":"AAAA","name":"One","current":true},{"providerId":2,"publicProviderId":"BBBB","name":"Two","current":false}]}`
	if got := strings.TrimSpace(stdout); got != want {
		t.Fatalf("stdout = %s, want %s", got, want)
	}
}

func TestWebAppsCreateSelectsProviderAndExplainsServerError(t *testing.T) {
	origResolveAppCreateSession := resolveAppCreateSessionFn
	origNewWebClient := newWebClientFn
	origEnsureBundleID := ensureBundleIDFn
	origSelect := selectWebProviderFn
	origPersist := persistWebSessionFn
	t.Cleanup(func() {
		resolveAppCreateSessionFn = origResolveAppCreateSession
		newWebClientFn = origNewWebClient
		ensureBundleIDFn = origEnsureBundleID
		selectWebProviderFn = origSelect
		persistWebSessionFn = origPersist
	})
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
	})
	resolveAppCreateSessionFn = func(ctx context.Context, appleID, password, twoFactorCode string) (*webcore.AuthSession, string, error) {
		return &webcore.AuthSession{Client: &http.Client{Transport: transport}, ProviderID: 1, ProviderName: "Other Team", PublicProviderID: "OTHER"}, "cache", nil
	}
	var selected webcore.ProviderSelection
	selectWebProviderFn = func(_ context.Context, session *webcore.AuthSession, selection webcore.ProviderSelection) error {
		selected = selection
		session.ProviderID, session.ProviderName, session.PublicProviderID = 2, "Example Inc.", "EXAMPLE"
		return nil
	}
	persistWebSessionFn = func(*webcore.AuthSession) error { return nil }
	newWebClientFn = webcore.NewClient
	ensureBundleIDFn = func(context.Context, *shared.Deps, string, string, string) (bool, error) { return false, nil }
	t.Setenv("ASC_WEB_MIN_REQUEST_INTERVAL", "0")

	d, _, stderr := newWebTestDeps()
	err := RunAppsCreate(context.Background(), d, AppsCreateRunOptions{
		Name: "My App", BundleID: "com.example.app", SKU: "SKU123", Output: "json",
		Provider: webcore.ProviderSelection{ProviderName: "Example Inc."},
	})
	if selected.ProviderName != "Example Inc." {
		t.Fatalf("provider selection = %+v", selected)
	}
	if !strings.Contains(stderr.String(), `Provider: "Example Inc." (EXAMPLE)`) {
		t.Fatalf("stderr does not name the acting provider: %q", stderr.String())
	}
	if err == nil || !strings.Contains(err.Error(), `Apple returned 500 while the web session acts for provider "Example Inc." (EXAMPLE)`) || !strings.Contains(err.Error(), "asc web providers list") {
		t.Fatalf("error = %v", err)
	}
}
