package web

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

var listSessionProvidersFn = webcore.ListSessionProviders

// newWebProvidersCommand returns the App Store Connect providers command group.
func newWebProvidersCommand(d *shared.Deps) *ffcli.Command {
	fs := d.NewFlagSet("web providers", flag.ExitOnError)
	return &ffcli.Command{
		Name:       "providers",
		ShortUsage: "asc web providers <subcommand> [flags]",
		ShortHelp:  "List App Store Connect providers (teams) of the web session.",
		LongHelp: `List the App Store Connect providers (teams) the web session's Apple Account
can act for. App Store Connect web commands such as asc web apps create act for
the session's current provider.

Examples:
  asc web providers list
  asc web providers list --provider-name "Example Inc."
`,
		FlagSet:     fs,
		UsageFunc:   d.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{newWebProvidersListCommand(d)},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

func newWebProvidersListCommand(d *shared.Deps) *ffcli.Command {
	fs := d.NewFlagSet("web providers list", flag.ExitOnError)
	authFlags := bindWebSessionFlags(fs)
	output := d.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "asc web providers list [flags]",
		ShortHelp:  "List App Store Connect providers (teams) of the web session.",
		LongHelp: `List every App Store Connect provider (team) of the web session's Apple
Account with its numeric ID, public ID and name, and mark the current one.

Pass --provider-name, --public-provider-id or --provider-id to switch the cached
session to that provider first; later asc web commands then act for it.

Examples:
  asc web providers list
  asc web providers list --output json
  asc web providers list --public-provider-id "Z4N6A5FQKW"
`,
		FlagSet:   fs,
		UsageFunc: d.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return d.UsageError("web providers list does not accept positional arguments")
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return d.UsageError(err.Error())
			}
			session, requestCtx, cancel, err := resolveWebSessionForCommandWith(ctx, d, authFlags)
			defer cancel()
			if err != nil {
				return withWebAuthHint(err, "web providers list")
			}
			providers, err := listSessionProvidersFn(requestCtx, session)
			if err != nil {
				return withWebAuthHint(err, "web providers list")
			}
			result := &asc.WebProvidersResult{Providers: make([]asc.WebProvider, 0, len(providers))}
			for _, provider := range providers {
				result.Providers = append(result.Providers, asc.WebProvider{
					ProviderID:       provider.ProviderID,
					PublicProviderID: provider.PublicProviderID,
					Name:             provider.Name,
					Current:          provider.Current,
				})
			}
			return d.PrintOutput(result, *output.Output, *output.Pretty)
		},
	}
}
