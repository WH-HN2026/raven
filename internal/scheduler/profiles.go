package scheduler

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nmap"
)

type ProfileInput struct {
	Name               string    `json:"name"`
	Ports              string    `json:"ports"`
	NmapMaxRate        *int32    `json:"nmap_max_rate"`
	NucleiRate         *int32    `json:"nuclei_rate"`
	NucleiTags         *[]string `json:"nuclei_tags"`
	MissThreshold      *int32    `json:"miss_threshold"`
	TargetBatchSeconds *int32    `json:"target_batch_seconds"`
	Enabled            *bool     `json:"enabled"`
}

func (in ProfileInput) apply(p gen.Profile) (gen.Profile, error) {
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
	p.Name, p.Ports, p.NucleiTags = name, ports, tags
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

func (s ConfigStore) CreateProfile(ctx context.Context, userID int64, in ProfileInput) (gen.Profile, error) {
	p, err := in.apply(gen.Profile{
		NmapMaxRate: 300, NucleiRate: 50, NucleiTags: []string{},
		MissThreshold: 3, TargetBatchSeconds: 600, Enabled: true,
	})
	if err != nil {
		return gen.Profile{}, err
	}
	err = s.write(ctx, func(q *gen.Queries) error {
		p, err = q.CreateProfile(ctx, gen.CreateProfileParams{
			Name: p.Name, Ports: p.Ports, NmapMaxRate: p.NmapMaxRate, NucleiRate: p.NucleiRate,
			NucleiTags: p.NucleiTags, MissThreshold: p.MissThreshold, TargetBatchSeconds: p.TargetBatchSeconds,
			Enabled: p.Enabled,
		})
		if dbCode(err, "23505") {
			return fmt.Errorf("%w: profile name already exists", ErrConflict)
		}
		if err != nil {
			return err
		}
		return logConfigChange(ctx, q, userID, "profiles.create", "profile", p.ID, p)
	})
	return p, err
}

func (s ConfigStore) UpdateProfile(ctx context.Context, userID, id int64, in ProfileInput) (gen.Profile, error) {
	var updated gen.Profile
	err := s.write(ctx, func(q *gen.Queries) error {
		p, err := q.LockProfile(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: profile %d", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		p, err = in.apply(p)
		if err != nil {
			return err
		}
		updated, err = q.UpdateProfile(ctx, gen.UpdateProfileParams{
			ID: id, Name: p.Name, Ports: p.Ports, NmapMaxRate: p.NmapMaxRate, NucleiRate: p.NucleiRate,
			NucleiTags: p.NucleiTags, MissThreshold: p.MissThreshold, TargetBatchSeconds: p.TargetBatchSeconds,
			Enabled: p.Enabled,
		})
		if dbCode(err, "23505") {
			return fmt.Errorf("%w: profile name already exists", ErrConflict)
		}
		if err != nil {
			return err
		}
		return logConfigChange(ctx, q, userID, "profiles.update", "profile", id, updated)
	})
	return updated, err
}

func (s ConfigStore) DeleteProfile(ctx context.Context, userID, id int64) error {
	return s.write(ctx, func(q *gen.Queries) error {
		if _, err := q.LockProfileForDelete(ctx, id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: profile %d", ErrNotFound, id)
			}
			return err
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
		return logConfigChange(ctx, q, userID, "profiles.delete", "profile", id, nil)
	})
}
