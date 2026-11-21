package dojo

import (
	"context"
	"log/slog"
	"time"
)

// PlanningAssetName is the Asset whose Engagements are planned scans (D9).
const PlanningAssetName = "RAVEN Planning"

type BootstrapConfig struct {
	URL          string
	Token        string // empty = obtain with AdminUser/AdminPassword
	AdminUser    string
	AdminPass    string
	Organization string
	RetryEvery   time.Duration
}

// BootstrapResult is what startup learned; later tasks wire Client from it.
type BootstrapResult struct {
	Client       *HTTPClient
	Organization *Organization
	Planning     *Asset
}

// Bootstrap waits for Dojo (its first boot runs migrations for minutes),
// obtains a token if none is configured, then get-or-creates the RAVEN
// organization and the "RAVEN Planning" asset. It retries until ctx is done, so
// run it in a goroutine: it must never block the HTTP server.
func Bootstrap(ctx context.Context, cfg BootstrapConfig) (*BootstrapResult, error) {
	if cfg.RetryEvery == 0 {
		cfg.RetryEvery = 10 * time.Second
	}
	for attempt := 1; ; attempt++ {
		res, err := bootstrapOnce(ctx, cfg)
		if err == nil {
			slog.Info("dojo bootstrap done",
				"organization", res.Organization.Name, "organization_id", res.Organization.ID,
				"planning_asset_id", res.Planning.ID)
			return res, nil
		}
		slog.Info("dojo not ready, retrying", "attempt", attempt, "in", cfg.RetryEvery, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(cfg.RetryEvery):
		}
	}
}

func bootstrapOnce(ctx context.Context, cfg BootstrapConfig) (*BootstrapResult, error) {
	token := cfg.Token
	if token == "" {
		var err error
		if token, err = ObtainToken(ctx, cfg.URL, cfg.AdminUser, cfg.AdminPass); err != nil {
			return nil, err
		}
		slog.Info("dojo token obtained with admin credentials", "user", cfg.AdminUser)
	}
	c := NewHTTPClient(cfg.URL, token)
	org, err := c.GetOrCreateOrganization(ctx, cfg.Organization)
	if err != nil {
		return nil, err
	}
	planning, err := c.GetOrCreateAsset(ctx, AssetSpec{
		Name:           PlanningAssetName,
		Description:    "Planned RAVEN scans: engagements tagged raven-profile:<name> become schedule windows.",
		OrganizationID: org.ID,
		Tags:           []string{"raven"},
	})
	if err != nil {
		return nil, err
	}
	return &BootstrapResult{Client: c, Organization: org, Planning: planning}, nil
}
