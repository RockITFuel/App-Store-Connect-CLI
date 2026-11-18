package asc

import "strconv"

// WebPushKeyReceipt holds only non-secret APNs key metadata and the local P8 path.
type WebPushKeyReceipt struct {
	KeyID       string `json:"keyId"`
	TeamID      string `json:"teamId"`
	Name        string `json:"name,omitempty"`
	Environment string `json:"environment,omitempty"`
	P8Path      string `json:"p8Path"`
}

func webPushKeyReceiptRows(r *WebPushKeyReceipt) ([]string, [][]string) {
	headers := []string{"Key ID", "Team ID", "Name", "Environment", "P8 Path"}
	if r == nil {
		return headers, nil
	}
	return headers, [][]string{{r.KeyID, r.TeamID, r.Name, r.Environment, r.P8Path}}
}

// WebPushKey is one APNs key on the Developer Portal team.
type WebPushKey struct {
	KeyID       string `json:"keyId"`
	Name        string `json:"name"`
	CanDownload bool   `json:"canDownload"`
}

// WebPushKeysResult lists a team's APNs keys.
type WebPushKeysResult struct {
	TeamID string       `json:"teamId"`
	Keys   []WebPushKey `json:"keys"`
}

func webPushKeysRows(r *WebPushKeysResult) ([]string, [][]string) {
	headers := []string{"Key ID", "Name", "Can Download"}
	if r == nil {
		return headers, nil
	}
	rows := make([][]string, 0, len(r.Keys))
	for _, key := range r.Keys {
		rows = append(rows, []string{key.KeyID, key.Name, strconv.FormatBool(key.CanDownload)})
	}
	return headers, rows
}

// WebPushKeyRevokeResult confirms a revoked APNs key.
type WebPushKeyRevokeResult struct {
	KeyID   string `json:"keyId"`
	TeamID  string `json:"teamId"`
	Revoked bool   `json:"revoked"`
}

func webPushKeyRevokeRows(r *WebPushKeyRevokeResult) ([]string, [][]string) {
	headers := []string{"Key ID", "Team ID", "Revoked"}
	if r == nil {
		return headers, nil
	}
	return headers, [][]string{{r.KeyID, r.TeamID, strconv.FormatBool(r.Revoked)}}
}
