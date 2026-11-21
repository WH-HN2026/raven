package scheduler

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

type profileAudit struct {
	gen.Profile
	Aggressive bool `json:"aggressive,omitempty"`
}

type ProfileInput struct {
	Name               string    `json:"name"`
	Ports              string    `json:"ports"`
	NmapMaxRate        *int32    `json:"nmap_max_rate"`
	NucleiRate         *int32    `json:"nuclei_rate"`
	NucleiTags         *[]string `json:"nuclei_tags"`
	MissThreshold      *int32    `json:"miss_threshold"`
	TargetBatchSeconds *int32    `json:"target_batch_seconds"`
	Enabled            *bool     `json:"enabled"`
	Stages             *[]string `json:"stages"`
}

func (in ProfileInput) apply(p gen.Profile, validateStages func([]string) ([]string, error)) (gen.Profile, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return gen.Profile{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	ports := strings.TrimSpace(in.Ports)
	if err := nmap.CheckPorts(ports); err != nil {
		return gen.Profile{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// These tag names are also enforced by nuclei's scanner allowlist.
	tags := defaultTo(in.NucleiTags, p.NucleiTags)
	for _, tag := range tags {
		if !slices.Contains([]string{"tech", "panel", "ssl", "waf", "favicon"}, tag) {
			return gen.Profile{}, fmt.Errorf("%w: unsupported nuclei tag %q", ErrInvalid, tag)
		}
	}
	stages := p.Stages
	if in.Stages != nil {
		if validateStages == nil {
			return gen.Profile{}, fmt.Errorf("%w: stage validator is not configured", ErrInvalid)
		}
		norm, err := validateStages(*in.Stages)
		if err != nil {
			return gen.Profile{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		stages = norm
	}
	p.Name, p.Ports, p.NucleiTags, p.Stages = name, ports, tags, stages
	p.NmapMaxRate = defaultTo(in.NmapMaxRate, p.NmapMaxRate)
	p.NucleiRate = defaultTo(in.NucleiRate, p.NucleiRate)
	p.MissThreshold = defaultTo(in.MissThreshold, p.MissThreshold)
	p.TargetBatchSeconds = defaultTo(in.TargetBatchSeconds, p.TargetBatchSeconds)
	p.Enabled = defaultTo(in.Enabled, p.Enabled)
	if p.NmapMaxRate < 1 || p.NmapMaxRate > 1_000_000 {
		return gen.Profile{}, fmt.Errorf("%w: nmap_max_rate must be between 1 and 1000000", ErrInvalid)
	}
	if p.NucleiRate < 1 || p.MissThreshold < 1 || p.TargetBatchSeconds < 1 {
		return gen.Profile{}, fmt.Errorf("%w: nuclei_rate, miss_threshold and target_batch_seconds must be positive", ErrInvalid)
	}
	return p, nil
}

func (s ConfigStore) defaultStages() []string {
	if s.DefaultStages != nil {
		return s.DefaultStages()
	}
	return []string{"nmap", "httpx", "nuclei"}
}

func (s ConfigStore) CreateProfile(ctx context.Context, u *auth.User, in ProfileInput) (gen.Profile, error) {
	p, err := in.apply(gen.Profile{
		NmapMaxRate: 300, NucleiRate: 50, NucleiTags: []string{},
		MissThreshold: 3, TargetBatchSeconds: 600, Enabled: true,
		Stages: s.defaultStages(),
	}, s.ValidateStages)
	if err != nil {
		return gen.Profile{}, err
	}
	aggressive := s.isAggressive(p.Stages)
	if aggressive && !canAggressive(u) {
		return gen.Profile{}, fmt.Errorf("%w: aggressive profiles need %s", ErrForbidden, auth.PermScanAggressive)
	}
	err = s.write(ctx, func(q *gen.Queries) error {
		p, err = q.CreateProfile(ctx, gen.CreateProfileParams{
			Name: p.Name, Ports: p.Ports, NmapMaxRate: p.NmapMaxRate, NucleiRate: p.NucleiRate,
			NucleiTags: p.NucleiTags, MissThreshold: p.MissThreshold, TargetBatchSeconds: p.TargetBatchSeconds,
			Enabled: p.Enabled, Stages: p.Stages,
		})
		if dbCode(err, "23505") {
			return fmt.Errorf("%w: profile name already exists", ErrConflict)
		}
		if err != nil {
			return err
		}
		return logConfigChange(ctx, q, u, "profiles.create", "profile", p.ID, profileAudit{Profile: p, Aggressive: aggressive})
	})
	return p, err
}

func (s ConfigStore) UpdateProfile(ctx context.Context, u *auth.User, id int64, in ProfileInput) (gen.Profile, error) {
	var updated gen.Profile
	err := s.write(ctx, func(q *gen.Queries) error {
		prior, err := q.LockProfile(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: profile %d", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if len(prior.Stages) == 0 {
			prior.Stages = s.defaultStages()
		}
		wasAggressive := s.isAggressive(prior.Stages)
		p, err := in.apply(prior, s.ValidateStages)
		if err != nil {
			return err
		}
		nowAggressive := s.isAggressive(p.Stages)
		if (wasAggressive || nowAggressive) && !canAggressive(u) {
			return fmt.Errorf("%w: aggressive profiles need %s", ErrForbidden, auth.PermScanAggressive)
		}
		updated, err = q.UpdateProfile(ctx, gen.UpdateProfileParams{
			ID: id, Name: p.Name, Ports: p.Ports, NmapMaxRate: p.NmapMaxRate, NucleiRate: p.NucleiRate,
			NucleiTags: p.NucleiTags, MissThreshold: p.MissThreshold, TargetBatchSeconds: p.TargetBatchSeconds,
			Enabled: p.Enabled, Stages: p.Stages,
		})
		if dbCode(err, "23505") {
			return fmt.Errorf("%w: profile name already exists", ErrConflict)
		}
		if err != nil {
			return err
		}
		return logConfigChange(ctx, q, u, "profiles.update", "profile", id, profileAudit{Profile: updated, Aggressive: wasAggressive || nowAggressive})
	})
	return updated, err
}

func (s ConfigStore) DeleteProfile(ctx context.Context, u *auth.User, id int64) error {
	return s.write(ctx, func(q *gen.Queries) error {
		prior, err := q.LockProfile(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: profile %d", ErrNotFound, id)
			}
			return err
		}
		aggressive := s.isAggressive(prior.Stages)
		if aggressive && !canAggressive(u) {
			return fmt.Errorf("%w: aggressive profiles need %s", ErrForbidden, auth.PermScanAggressive)
		}
		inUse, err := q.ProfileHasSchedules(ctx, id)
		if err != nil {
			return err
		}
		if inUse {
			return fmt.Errorf("%w: profile has schedules", ErrConflict)
		}
		if err := q.DeleteProfile(ctx, id); err != nil {
			if dbCode(err, "23503") {
				return fmt.Errorf("%w: profile has runs", ErrConflict)
			}
			return err
		}
		var diff any
		if aggressive {
			diff = map[string]any{"aggressive": true, "name": prior.Name, "stages": prior.Stages}
		}
		return logConfigChange(ctx, q, u, "profiles.delete", "profile", id, diff)
	})
}
