package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// pushKeyService is the Developer Portal service ID of Apple Push Notification
// service (APNs) authentication keys, as fastlane's portal client names it.
const pushKeyService = "U27F4V844T"

// PushKeyEnvironment is the APNs environment a push key may sign for.
type PushKeyEnvironment string

const (
	PushKeyEnvironmentSandbox    PushKeyEnvironment = "sandbox"
	PushKeyEnvironmentProduction PushKeyEnvironment = "production"
	PushKeyEnvironmentBoth       PushKeyEnvironment = "both"
)

// portalPushKeyEnvironments maps each environment to the value the Developer
// Portal create request takes (fastlane: "all", "production", "development").
var portalPushKeyEnvironments = map[PushKeyEnvironment]string{
	PushKeyEnvironmentSandbox:    "development",
	PushKeyEnvironmentProduction: "production",
	PushKeyEnvironmentBoth:       "all",
}

// ParsePushKeyEnvironment parses sandbox, production or both.
func ParsePushKeyEnvironment(value string) (PushKeyEnvironment, error) {
	env := PushKeyEnvironment(strings.ToLower(strings.TrimSpace(value)))
	if _, ok := portalPushKeyEnvironments[env]; !ok {
		return "", fmt.Errorf("environment must be sandbox, production or both")
	}
	return env, nil
}

// ListDeveloperPushKeys returns the team's APNs keys. The list response may
// omit services, so a key without them is read back individually.
func (c *Client) ListDeveloperPushKeys(ctx context.Context) ([]DeveloperSignInKey, error) {
	all, err := c.ListDeveloperSignInKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := []DeveloperSignInKey{}
	for _, key := range all.Keys {
		if len(key.Services) == 0 {
			detail, err := c.GetDeveloperSignInKey(ctx, key.KeyID)
			if err != nil {
				return nil, err
			}
			key = *detail
		}
		if key.HasService(pushKeyService) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// CreateDeveloperPushKey creates a team-scoped APNs key for env and verifies
// that the created key carries the APNs service.
func (c *Client) CreateDeveloperPushKey(ctx context.Context, name string, env PushKeyEnvironment) (*DeveloperSignInKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	portalEnv, ok := portalPushKeyEnvironments[env]
	if !ok {
		return nil, fmt.Errorf("environment must be sandbox, production or both")
	}
	existing, err := c.ListDeveloperSignInKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range existing.Keys {
		if key.KeyName == name {
			return nil, fmt.Errorf("key %s already has this name; inspect it instead of creating a duplicate", key.KeyID)
		}
	}
	payload := map[string]any{"teamId": c.developerPortalTeamID(), "name": name, "serviceConfigurationsRequests": []any{map[string]any{
		"isNew": true, "serviceId": pushKeyService, "identifiers": map[string]any{}, "environment": portalEnv, "scope": "team",
	}}}
	headers := developerPortalHeaders("")
	headers.Set("Content-Type", "application/json")
	if err := c.applyDeveloperPortalCSRF(headers, true); err != nil {
		return nil, err
	}
	body, err := c.doDeveloperPortalHTTPAndCapture(ctx, http.MethodPost, c.developerPortalOrigin()+developerPortalLegacyPath+"/account/auth/key/v2/create", payload, headers)
	if err != nil {
		return nil, fmt.Errorf("key creation outcome is unknown; inspect push-keys list before retrying: %w", err)
	}
	result, err := parseDeveloperSignInKeys(body)
	if err != nil {
		return nil, fmt.Errorf("inspect push-keys list before retrying: %w", err)
	}
	if len(result.Keys) != 1 {
		return nil, fmt.Errorf("key creation returned unexpected key count; inspect push-keys list before retrying")
	}
	keyID := result.Keys[0].KeyID
	detail, err := c.GetDeveloperSignInKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("key %s created, but configuration verification failed; inspect before retrying: %w", keyID, err)
	}
	if !detail.HasService(pushKeyService) {
		return nil, fmt.Errorf("key %s created, but the APNs service was not verified; inspect before retrying", keyID)
	}
	return detail, nil
}

// DownloadDeveloperPushKey consumes the one-time P8 download of an APNs key.
func (c *Client) DownloadDeveloperPushKey(ctx context.Context, keyID string) ([]byte, error) {
	return c.downloadDeveloperAuthKey(ctx, keyID, pushKeyService, "an APNs")
}

// RevokeDeveloperPushKey revokes an APNs key. It refuses keys of other
// services so a mistyped ID cannot revoke a Sign in with Apple or other key.
func (c *Client) RevokeDeveloperPushKey(ctx context.Context, keyID string) error {
	key, err := c.GetDeveloperSignInKey(ctx, keyID)
	if err != nil {
		return err
	}
	if !key.HasService(pushKeyService) {
		return fmt.Errorf("key %s is not an APNs key", keyID)
	}
	// List issues the key-family CSRF pair; the read-back above replaces it
	// with the team pair, so list again right before the write.
	if _, err := c.ListDeveloperSignInKeys(ctx); err != nil {
		return err
	}
	body, err := c.doDeveloperPortalLegacyFormRequest(ctx, "/account/auth/key/revoke", url.Values{"teamId": {c.developerPortalTeamID()}, "keyId": {keyID}}, true)
	if err != nil {
		return fmt.Errorf("key %s revocation outcome is unknown; inspect push-keys list before retrying: %w", keyID, err)
	}
	var envelope struct {
		ResultCode *int `json:"resultCode"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.ResultCode == nil {
		return fmt.Errorf("key %s revocation returned an invalid response; inspect push-keys list", keyID)
	}
	if *envelope.ResultCode != 0 {
		return fmt.Errorf("key %s revocation failed (result code %d)", keyID, *envelope.ResultCode)
	}
	return nil
}
