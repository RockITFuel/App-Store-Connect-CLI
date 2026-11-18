package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func providerSelectionTestInfo() *sessionInfo {
	return &sessionInfo{
		Provider: sessionProviderInfo{ProviderID: 1, PublicProviderID: "ONE1", Name: "Example One"},
		AvailableProviders: []sessionProviderInfo{
			{ProviderID: 1, PublicProviderID: "ONE1", Name: "Example One"},
			{ProviderID: 2, PublicProviderID: "TWO1", Name: "Example Two B.V."},
			{ProviderID: 3, PublicProviderID: "DUP1", Name: "Twin"},
			{ProviderID: 4, PublicProviderID: "DUP2", Name: "twin"},
		},
	}
}

func TestResolveProviderSelectionByName(t *testing.T) {
	info := providerSelectionTestInfo()
	got, err := resolveProviderSelection(info, ProviderSelection{ProviderName: " example two b.v. "})
	if err != nil || got.ProviderID != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = resolveProviderSelection(info, ProviderSelection{ProviderName: "Example Two B.V.", PublicProviderID: "TWO1"})
	if err != nil || got.ProviderID != 2 {
		t.Fatalf("name plus matching ID: got %+v, %v", got, err)
	}
	for _, tc := range []struct {
		selection ProviderSelection
		want      string
	}{
		{ProviderSelection{ProviderName: "Nope"}, "did not match any available providers"},
		{ProviderSelection{ProviderName: "Twin"}, "matches several providers"},
		{ProviderSelection{ProviderName: "Example Two B.V.", PublicProviderID: "ONE1"}, "provider selection mismatch"},
	} {
		_, err := resolveProviderSelection(info, tc.selection)
		if !errors.Is(err, ErrInvalidProviderSelection) || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v: error = %v, want %q", tc.selection, err, tc.want)
		}
	}
}

func TestListSessionProvidersMarksCurrent(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, []byte(`{"provider":{"providerId":1,"publicProviderId":"ONE1","name":"Example One"},"availableProviders":[{"providerId":1,"publicProviderId":"ONE1","name":"Example One"},{"providerId":2,"publicProviderId":"TWO1","name":"Example Two B.V."}],"user":{"emailAddress":"user@example.com"}}`), nil), nil
	})}
	providers, err := ListSessionProviders(context.Background(), &AuthSession{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 || !providers[0].Current || providers[1].Current || providers[1].Name != "Example Two B.V." || providers[1].PublicProviderID != "TWO1" {
		t.Fatalf("providers = %+v", providers)
	}
}
