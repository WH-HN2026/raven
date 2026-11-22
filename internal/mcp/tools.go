package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/hosts"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/targets"
)

type listResult[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

func boolPtr(b bool) *bool { return &b }

func userFromRequest(ctx context.Context, req *sdkmcp.CallToolRequest) *auth.User {
	if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
		if u, ok := req.Extra.TokenInfo.Extra[extraUserKey].(*auth.User); ok && u != nil {
			return u
		}
	}
	return auth.UserFrom(ctx)
}

func requirePerm(ctx context.Context, req *sdkmcp.CallToolRequest, perm auth.Permission) (*auth.User, error) {
	u := userFromRequest(ctx, req)
	if u == nil {
		return nil, errors.New("unauthenticated: valid API token required")
	}
	if !auth.Can(u.Role, perm) {
		return nil, fmt.Errorf("permission denied: role %q lacks %s", u.Role, perm)
	}
	return u, nil
}

func jsonResult(v any) (*sdkmcp.CallToolResult, any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal result: %w", err)
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func normalizePage(limit, offset, defLimit, maxLimit int) (int32, int32, error) {
	if limit == 0 {
		limit = defLimit
	}
	if limit < 1 || limit > maxLimit {
		return 0, 0, fmt.Errorf("limit must be 1..%d", maxLimit)
	}
	if offset < 0 {
		return 0, 0, errors.New("offset must be >= 0")
	}
	return int32(limit), int32(offset), nil
}

// SearchHostsInput holds filters matching GET /api/hosts.
type SearchHostsInput struct {
	Query  string `json:"query,omitempty" jsonschema:"IP, CIDR, IP prefix, or hostname substring"`
	State  string `json:"state,omitempty" jsonschema:"Host state filter: active, unstable, or inactive"`
	Port   *int   `json:"port,omitempty" jsonschema:"Filter hosts with an open service on this port (0-65535)"`
	Tech   string `json:"tech,omitempty" jsonschema:"Filter by detected technology (case-insensitive)"`
	Tag    string `json:"tag,omitempty" jsonschema:"Filter by exact user tag"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum results to return (1-1000, default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Pagination offset (>= 0, default 0)"`
}

// GetHostInput identifies a host by IP.
type GetHostInput struct {
	IP string `json:"ip" jsonschema:"Host IP address"`
}

// HostDetailOutput combines host detail, services, HTTP observations, timeline, and CVE matches.
type HostDetailOutput struct {
	*hosts.Detail
	CVEMatches []cve.Match `json:"cve_matches"`
}

// ListFindingsInput holds filters matching GET /api/findings (mirror read only).
type ListFindingsInput struct {
	Severity     string `json:"severity,omitempty" jsonschema:"Comma-separated severities: Critical, High, Medium, Low, Info"`
	Active       *bool  `json:"active,omitempty" jsonschema:"Filter by active status"`
	Verified     *bool  `json:"verified,omitempty" jsonschema:"Filter by verified status"`
	FalseP       *bool  `json:"false_p,omitempty" jsonschema:"Filter by false positive status"`
	OutOfScope   *bool  `json:"out_of_scope,omitempty" jsonschema:"Filter by out of scope status"`
	RiskAccepted *bool  `json:"risk_accepted,omitempty" jsonschema:"Filter by risk accepted status"`
	Duplicate    *bool  `json:"duplicate,omitempty" jsonschema:"Filter by duplicate status"`
	IsMitigated  *bool  `json:"is_mitigated,omitempty" jsonschema:"Filter by mitigated status"`
	IP           string `json:"ip,omitempty" jsonschema:"Filter by IP address or CIDR"`
	Search       string `json:"search,omitempty" jsonschema:"Case-insensitive title substring"`
	Scanner      string `json:"scanner,omitempty" jsonschema:"Filter by scanner name"`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum results to return (1-1000, default 50)"`
	Offset       int    `json:"offset,omitempty" jsonschema:"Pagination offset (>= 0, default 0)"`
}

// GetChangesInput specifies the two runs to compare.
type GetChangesInput struct {
	FromRunID *int64 `json:"from_run_id,omitempty" jsonschema:"Older run ID (optional; defaults to previous finished run)"`
	ToRunID   *int64 `json:"to_run_id,omitempty" jsonschema:"Newer run ID (optional; defaults to latest finished run)"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum items per change list (1-5000, default 1000)"`
}

// ListRunsInput holds filters matching GET /api/runs.
type ListRunsInput struct {
	ProfileID *int64 `json:"profile_id,omitempty" jsonschema:"Filter runs by profile ID"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum results to return (1-1000, default 50)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Pagination offset (>= 0, default 0)"`
}

// StartScanInput starts a scan run for a profile.
type StartScanInput struct {
	ProfileID int64 `json:"profile_id" jsonschema:"Profile ID to scan"`
}

// TargetInput is one target entry for add_targets.
type TargetInput struct {
	Value string   `json:"value" jsonschema:"IP address, CIDR, or domain name"`
	Kind  string   `json:"kind,omitempty" jsonschema:"Optional target kind: ip, cidr, or domain (auto-detected if omitted)"`
	Tags  []string `json:"tags,omitempty" jsonschema:"Optional target tags"`
	Note  string   `json:"note,omitempty" jsonschema:"Optional operator note"`
}

// AddTargetsInput adds one or more targets atomically.
type AddTargetsInput struct {
	Targets []TargetInput `json:"targets" jsonschema:"Targets to validate and add"`
}

func registerTools(s *sdkmcp.Server, d Deps) {
	readAnnotations := &sdkmcp.ToolAnnotations{
		ReadOnlyHint:  true,
		OpenWorldHint: boolPtr(false),
	}
	writeAnnotations := &sdkmcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(false),
		OpenWorldHint:   boolPtr(false),
	}

	// 1. search_hosts
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "search_hosts",
		Description: "Search discovered hosts by query (IP/CIDR/hostname), state, open port, technology, or user tag.",
		Annotations: readAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in SearchHostsInput) (*sdkmcp.CallToolResult, any, error) {
		if _, err := requirePerm(ctx, req, auth.PermRead); err != nil {
			return nil, nil, err
		}
		if d.Pool == nil {
			return nil, nil, errors.New("database is not configured")
		}
		limit, offset, err := normalizePage(in.Limit, in.Offset, 50, 1000)
		if err != nil {
			return nil, nil, err
		}
		f := hosts.Filter{
			Tech:   strings.TrimSpace(in.Tech),
			Tag:    strings.TrimSpace(in.Tag),
			Q:      strings.TrimSpace(in.Query),
			Limit:  limit,
			Offset: offset,
		}
		if st := strings.TrimSpace(in.State); st != "" {
			if !slices.Contains(hosts.States, st) {
				return nil, nil, fmt.Errorf("state must be one of %s", strings.Join(hosts.States, ", "))
			}
			f.State = st
		}
		if in.Port != nil {
			if *in.Port < 0 || *in.Port > 65535 {
				return nil, nil, errors.New("port must be 0..65535")
			}
			f.Port = in.Port
		}
		items, total, err := hosts.List(ctx, d.Pool, f)
		if err != nil {
			return nil, nil, fmt.Errorf("search hosts: %w", err)
		}
		return jsonResult(listResult[hosts.Host]{Items: items, Total: total})
	})

	// 2. get_host
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "get_host",
		Description: "Get full detail for a host by IP address, including services, latest HTTP observations, run timeline, and offline CVE matches.",
		Annotations: readAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in GetHostInput) (*sdkmcp.CallToolResult, any, error) {
		if _, err := requirePerm(ctx, req, auth.PermRead); err != nil {
			return nil, nil, err
		}
		if d.Pool == nil {
			return nil, nil, errors.New("database is not configured")
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(in.IP))
		if err != nil {
			return nil, nil, errors.New("ip must be a valid IP address")
		}
		detail, err := hosts.Get(ctx, d.Pool, ip)
		if err != nil {
			if errors.Is(err, hosts.ErrNotFound) {
				return nil, nil, fmt.Errorf("host %s not found", ip.Unmap())
			}
			return nil, nil, fmt.Errorf("get host %s: %w", ip.Unmap(), err)
		}
		matches, err := cve.List(ctx, d.Pool, ip)
		if err != nil {
			return nil, nil, fmt.Errorf("list cve matches for %s: %w", ip.Unmap(), err)
		}
		if matches == nil {
			matches = []cve.Match{}
		}
		return jsonResult(HostDetailOutput{Detail: detail, CVEMatches: matches})
	})

	// 3. list_findings (reads dojo_findings mirror only, never calls Dojo)
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "list_findings",
		Description: "List security findings from the local DefectDojo mirror filtered by severity, status, IP/CIDR, title search, or scanner.",
		Annotations: readAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in ListFindingsInput) (*sdkmcp.CallToolResult, any, error) {
		if _, err := requirePerm(ctx, req, auth.PermRead); err != nil {
			return nil, nil, err
		}
		if d.Pool == nil {
			return nil, nil, errors.New("database is not configured")
		}
		limit, offset, err := normalizePage(in.Limit, in.Offset, 50, 1000)
		if err != nil {
			return nil, nil, err
		}
		f := dojo.FindingFilter{
			Active:       in.Active,
			Verified:     in.Verified,
			FalseP:       in.FalseP,
			OutOfScope:   in.OutOfScope,
			RiskAccepted: in.RiskAccepted,
			Duplicate:    in.Duplicate,
			IsMitigated:  in.IsMitigated,
			Q:            strings.TrimSpace(in.Search),
			Scanner:      strings.TrimSpace(in.Scanner),
			Limit:        limit,
			Offset:       offset,
		}
		if sev := strings.TrimSpace(in.Severity); sev != "" {
			for s := range strings.SplitSeq(sev, ",") {
				if s = strings.TrimSpace(s); s == "" {
					continue
				}
				i := slices.IndexFunc(dojo.Severities, func(x string) bool { return strings.EqualFold(x, s) })
				if i < 0 {
					return nil, nil, fmt.Errorf("severity must be one of %s", strings.Join(dojo.Severities, ", "))
				}
				f.Severities = append(f.Severities, dojo.Severities[i])
			}
		}
		if v := strings.TrimSpace(in.IP); v != "" {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				addr, aerr := netip.ParseAddr(v)
				if aerr != nil {
					return nil, nil, errors.New("ip must be an IP address or CIDR")
				}
				addr = addr.Unmap()
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			f.IP = &p
		}
		items, total, err := dojo.ListMirrorFindings(ctx, d.Pool, f, d.DojoPublicURL)
		if err != nil {
			return nil, nil, fmt.Errorf("list findings: %w", err)
		}
		return jsonResult(listResult[dojo.MirrorFinding]{Items: items, Total: total})
	})

	// 4. get_changes
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "get_changes",
		Description: "Compare two scan runs (from_run_id -> to_run_id) to list new, gone, and changed hosts and services.",
		Annotations: readAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in GetChangesInput) (*sdkmcp.CallToolResult, any, error) {
		if _, err := requirePerm(ctx, req, auth.PermRead); err != nil {
			return nil, nil, err
		}
		q := d.Queries
		if q == nil && d.Pool != nil {
			q = gen.New(d.Pool)
		}
		if q == nil {
			return nil, nil, errors.New("database is not configured")
		}
		if in.FromRunID != nil && *in.FromRunID < 1 {
			return nil, nil, errors.New("from_run_id must be a positive run id")
		}
		if in.ToRunID != nil && *in.ToRunID < 1 {
			return nil, nil, errors.New("to_run_id must be a positive run id")
		}
		limit, _, err := normalizePage(in.Limit, 0, 1000, 5000)
		if err != nil {
			return nil, nil, err
		}
		diff, err := changes.Compare(ctx, q, in.FromRunID, in.ToRunID, int(limit))
		if err != nil {
			return nil, nil, fmt.Errorf("get changes: %w", err)
		}
		return jsonResult(diff)
	})

	// 5. list_runs
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "list_runs",
		Description: "List scan runs (newest first), optionally filtered by profile_id.",
		Annotations: readAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in ListRunsInput) (*sdkmcp.CallToolResult, any, error) {
		if _, err := requirePerm(ctx, req, auth.PermRead); err != nil {
			return nil, nil, err
		}
		if d.Pipeline == nil {
			return nil, nil, errors.New("scan pipeline is not running")
		}
		if in.ProfileID != nil && *in.ProfileID < 1 {
			return nil, nil, errors.New("profile_id must be a positive integer")
		}
		limit, offset, err := normalizePage(in.Limit, in.Offset, 50, 1000)
		if err != nil {
			return nil, nil, err
		}
		items, total, err := d.Pipeline.ListRuns(ctx, in.ProfileID, limit, offset, db.ListOrder{})
		if err != nil {
			return nil, nil, fmt.Errorf("list runs: %w", err)
		}
		return jsonResult(listResult[pipeline.Run]{Items: items, Total: total})
	})

	// 6. start_scan (editor+)
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "start_scan",
		Description: "Start a scan run for a profile (requires runs:control).",
		Annotations: writeAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in StartScanInput) (*sdkmcp.CallToolResult, any, error) {
		u, err := requirePerm(ctx, req, auth.PermRunsControl)
		if err != nil {
			return nil, nil, err
		}
		if d.Pipeline == nil {
			return nil, nil, errors.New("scan pipeline is not running")
		}
		if in.ProfileID < 1 {
			return nil, nil, errors.New("profile_id must be a positive integer")
		}
		run, err := d.Pipeline.StartRun(ctx, u, in.ProfileID)
		if err != nil {
			return nil, nil, fmt.Errorf("start scan: %w", err)
		}
		return jsonResult(run)
	})

	// 7. add_targets (editor+)
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "add_targets",
		Description: "Validate and add one or more scan targets (IP, CIDR, or domain) atomically (requires targets:write).",
		Annotations: writeAnnotations,
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in AddTargetsInput) (*sdkmcp.CallToolResult, any, error) {
		u, err := requirePerm(ctx, req, auth.PermTargetsWrite)
		if err != nil {
			return nil, nil, err
		}
		if d.Pool == nil {
			return nil, nil, errors.New("database is not configured")
		}
		if len(in.Targets) == 0 {
			return nil, nil, errors.New("targets must not be empty")
		}
		entries := make([]targets.Entry, 0, len(in.Targets))
		for i, t := range in.Targets {
			e, err := targets.NewEntry(t.Value, targets.Kind(t.Kind), t.Tags, t.Note)
			if err != nil {
				return nil, nil, fmt.Errorf("target %d (%q): %w", i+1, t.Value, err)
			}
			entries = append(entries, e)
		}
		store := &targets.Store{Pool: d.Pool, IsAggressive: pipeline.IsAggressive}
		created, err := store.AddTargets(ctx, u, "manual", entries)
		if err != nil {
			return nil, nil, fmt.Errorf("add targets: %w", err)
		}
		return jsonResult(listResult[gen.Target]{Items: created, Total: int64(len(created))})
	})
}
