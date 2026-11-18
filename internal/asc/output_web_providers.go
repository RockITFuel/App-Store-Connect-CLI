package asc

import "strconv"

// WebProvider is one App Store Connect provider (team) of the web session's
// Apple Account.
type WebProvider struct {
	ProviderID       int64  `json:"providerId"`
	PublicProviderID string `json:"publicProviderId,omitempty"`
	Name             string `json:"name"`
	Current          bool   `json:"current"`
}

// WebProvidersResult lists the providers a web session can act for.
type WebProvidersResult struct {
	Providers []WebProvider `json:"providers"`
}

func webProvidersRows(r *WebProvidersResult) ([]string, [][]string) {
	headers := []string{"Provider ID", "Public Provider ID", "Name", "Current"}
	if r == nil {
		return headers, nil
	}
	rows := make([][]string, 0, len(r.Providers))
	for _, provider := range r.Providers {
		rows = append(rows, []string{strconv.FormatInt(provider.ProviderID, 10), provider.PublicProviderID, provider.Name, strconv.FormatBool(provider.Current)})
	}
	return headers, rows
}
