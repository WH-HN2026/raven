package dojo

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/WH-HN2026/raven/internal/targets"
)

// TargetClient is the subset of Client needed to import targets from DefectDojo.
// Client, WriteClient and *HTTPClient all satisfy it.
type TargetClient interface {
	ListAssets(ctx context.Context, q AssetQuery) (*Page[Asset], error)
	ListURLs(ctx context.Context, q URLQuery) (*Page[URL], error)
}

// FetchedTargets is the deduplicated set of valid targets pulled from DefectDojo
// along with the count of invalid/non-target candidates skipped.
type FetchedTargets struct {
	Entries []targets.Entry
	Skipped int
}

// FetchTargets pages through all DefectDojo Assets (across all organizations)
// and URL Locations (/api/v2/url/), validates each candidate (asset name or
// URL host) via targets.NewEntry, deduplicates by (kind, value) while merging
// non-internal tags, and counts invalid/non-target names in Skipped.
func FetchTargets(ctx context.Context, c TargetClient) (*FetchedTargets, error) {
	if c == nil {
		return nil, ErrNotReady
	}
	assets, err := pageAll(ctx, func(limit, offset int) (*Page[Asset], error) {
		return c.ListAssets(ctx, AssetQuery{Limit: limit, Offset: offset})
	})
	if err != nil {
		return nil, fmt.Errorf("dojo fetch targets (assets): %w", err)
	}
	urls, err := pageAll(ctx, func(limit, offset int) (*Page[URL], error) {
		return c.ListURLs(ctx, URLQuery{Limit: limit, Offset: offset})
	})
	if err != nil {
		return nil, fmt.Errorf("dojo fetch targets (urls): %w", err)
	}

	out := &FetchedTargets{Entries: []targets.Entry{}}
	index := map[string]int{}
	add := func(raw string, tags []string) {
		e, err := targets.NewEntry(raw, "", filterTargetTags(tags), "")
		if err != nil {
			out.Skipped++
			return
		}
		key := string(e.Kind) + " " + e.Value
		if i, ok := index[key]; ok {
			merged := append(append([]string{}, out.Entries[i].Tags...), e.Tags...)
			out.Entries[i].Tags = dedupSortedTags(merged)
			return
		}
		index[key] = len(out.Entries)
		out.Entries = append(out.Entries, e)
	}

	for _, a := range assets {
		add(a.Name, a.Tags)
	}
	for _, u := range urls {
		add(u.Host, u.Tags)
	}
	return out, nil
}

// filterTargetTags drops RAVEN-managed internal asset tags (raven, asi, host:*,
// tech:*, panel:*, env:*, cve:*, raven-profile:*, asi-profile:*) and unwraps
// user:<tag> prefixes so imported target tags stay clean.
func filterTargetTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		lower := strings.ToLower(t)
		if lower == SyncTag || lower == "asi" ||
			strings.HasPrefix(lower, "host:") ||
			strings.HasPrefix(lower, "tech:") ||
			strings.HasPrefix(lower, "panel:") ||
			strings.HasPrefix(lower, "env:") ||
			strings.HasPrefix(lower, "cve:") ||
			strings.HasPrefix(lower, "raven-profile:") ||
			strings.HasPrefix(lower, "asi-profile:") {
			continue
		}
		if strings.HasPrefix(lower, UserTagPrefix) {
			t = strings.TrimSpace(t[len(UserTagPrefix):])
			if t == "" {
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

func dedupSortedTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}
