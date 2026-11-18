package web

import (
	"context"
	"flag"
	"regexp"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

var (
	listDeveloperPushKeysFn = func(ctx context.Context, client *webcore.Client) ([]webcore.DeveloperSignInKey, error) {
		return client.ListDeveloperPushKeys(ctx)
	}
	createDeveloperPushKeyFn = func(ctx context.Context, client *webcore.Client, name string, env webcore.PushKeyEnvironment) (*webcore.DeveloperSignInKey, error) {
		return client.CreateDeveloperPushKey(ctx, name, env)
	}
	downloadDeveloperPushKeyFn = func(ctx context.Context, client *webcore.Client, keyID string) ([]byte, error) {
		return client.DownloadDeveloperPushKey(ctx, keyID)
	}
	revokeDeveloperPushKeyFn = func(ctx context.Context, client *webcore.Client, keyID string) error {
		return client.RevokeDeveloperPushKey(ctx, keyID)
	}
)

var pushAuthKeyKind = authKeyKind{
	group: "push-keys", label: "APNs", article: "an", environment: true,
	create: func(ctx context.Context, client *webcore.Client, req authKeyCreateRequest) (*webcore.DeveloperSignInKey, error) {
		return createDeveloperPushKeyFn(ctx, client, req.Name, req.Environment)
	},
	fetch: func(ctx context.Context, client *webcore.Client, keyID string) ([]byte, error) {
		return downloadDeveloperPushKeyFn(ctx, client, keyID)
	},
	receipt: func(client *webcore.Client, req authKeyCreateRequest, keyID, p8Path string) any {
		return &asc.WebPushKeyReceipt{KeyID: keyID, TeamID: client.DeveloperPortalTeamID(), Name: req.Name, Environment: string(req.Environment), P8Path: p8Path}
	},
}

func newWebPushKeysCommand(d *shared.Deps) *ffcli.Command {
	return &ffcli.Command{
		Name:       "push-keys",
		ShortUsage: "asc web push-keys <subcommand> [flags]",
		ShortHelp:  "Create, list, download and revoke APNs push notification keys through Developer Portal.",
		LongHelp: `APNs keys are team scoped. Each command acts for the --developer-team
selection (see asc web teams list).

Examples:
  asc web push-keys list --developer-team TEAM_ID
  asc web push-keys create --name "Production push" --environment production --output-dir ./keys --confirm --developer-team TEAM_ID
  asc web push-keys revoke --key-id KEY_ID --confirm --developer-team TEAM_ID`,
		FlagSet:   d.NewFlagSet("web push-keys", flag.ExitOnError),
		UsageFunc: d.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{
			newWebPushKeysListCommand(d),
			webAuthKeySaveCommand(d, pushAuthKeyKind, true),
			webAuthKeySaveCommand(d, pushAuthKeyKind, false),
			newWebPushKeysRevokeCommand(d),
		},
		Exec: func(context.Context, []string) error { return flag.ErrHelp },
	}
}

func newWebPushKeysListCommand(d *shared.Deps) *ffcli.Command {
	fs := d.NewFlagSet("web push-keys list", flag.ExitOnError)
	authFlags := bindWebSessionFlags(fs)
	portalFlags := bindDeveloperPortalFlags(fs)
	output := d.BindOutputFlags(fs)
	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "asc web push-keys list [flags]",
		ShortHelp:  "List the team's APNs keys and whether their P8 can still be downloaded.",
		FlagSet:    fs,
		UsageFunc:  d.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if err := validateDeveloperPortalFlagsWith(d, portalFlags); err != nil {
				return err
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return d.UsageError(err.Error())
			}
			session, requestCtx, cancel, err := resolveWebSessionForCommandWith(ctx, d, authFlags)
			defer cancel()
			if err != nil {
				return err
			}
			client := newDeveloperPortalClient(session, portalFlags)
			keys, err := listDeveloperPushKeysFn(requestCtx, client)
			if err != nil {
				return withWebAuthHint(err, "web push-keys list")
			}
			persistDeveloperPortalSessionWith(d, session)
			result := &asc.WebPushKeysResult{TeamID: client.DeveloperPortalTeamID(), Keys: make([]asc.WebPushKey, 0, len(keys))}
			for _, key := range keys {
				result.Keys = append(result.Keys, asc.WebPushKey{KeyID: key.KeyID, Name: key.KeyName, CanDownload: key.CanDownload})
			}
			return d.PrintOutput(result, *output.Output, *output.Pretty)
		},
	}
}

func newWebPushKeysRevokeCommand(d *shared.Deps) *ffcli.Command {
	fs := d.NewFlagSet("web push-keys revoke", flag.ExitOnError)
	authFlags := bindWebSessionFlags(fs)
	portalFlags := bindDeveloperPortalFlags(fs)
	output := d.BindOutputFlags(fs)
	keyID := fs.String("key-id", "", "APNs key ID")
	confirm := fs.Bool("confirm", false, "Confirm revoking this APNs key; servers signing with it stop delivering pushes")
	return &ffcli.Command{
		Name:       "revoke",
		ShortUsage: "asc web push-keys revoke --key-id ID --confirm [flags]",
		ShortHelp:  "Revoke an APNs key. Refuses keys of other services.",
		FlagSet:    fs,
		UsageFunc:  d.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			id := strings.TrimSpace(*keyID)
			if id == "" {
				return d.UsageError("--key-id is required")
			}
			if !regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`).MatchString(id) {
				return d.UsageError("invalid --key-id")
			}
			if err := d.RequireConfirm(*confirm); err != nil {
				return err
			}
			if err := validateDeveloperPortalFlagsWith(d, portalFlags); err != nil {
				return err
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return d.UsageError(err.Error())
			}
			session, requestCtx, cancel, err := resolveWebSessionForCommandWith(ctx, d, authFlags)
			defer cancel()
			if err != nil {
				return err
			}
			client := newDeveloperPortalClient(session, portalFlags)
			if err := revokeDeveloperPushKeyFn(requestCtx, client, id); err != nil {
				return withWebAuthHint(err, "web push-keys revoke")
			}
			persistDeveloperPortalSessionWith(d, session)
			return d.PrintOutput(&asc.WebPushKeyRevokeResult{KeyID: id, TeamID: client.DeveloperPortalTeamID(), Revoked: true}, *output.Output, *output.Pretty)
		},
	}
}
