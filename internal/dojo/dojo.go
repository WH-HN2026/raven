// Package dojo talks to DefectDojo 3.5 API v2 (D4). This file defines the
// client interface and the wire types; http.go has the concrete HTTPClient.
//
// Naming in 3.5.202: organizations/ and assets/ are the new endpoints for
// Product_Type/Product. Engagement, test and import-scan payloads still use
// the old field names ("product", "product_name", "product_type_name").
package dojo

import (
	"context"
	"io"
	"time"
)

// Client is the DefectDojo API surface RAVEN uses (architecture §4).
type Client interface {
	GetOrCreateOrganization(ctx context.Context, name string) (*Organization, error)
	GetOrCreateAsset(ctx context.Context, a AssetSpec) (*Asset, error)
	GetOrCreateEngagement(ctx context.Context, e EngagementSpec) (*Engagement, error)
	GetOrCreateTest(ctx context.Context, t TestSpec) (*Test, error)

	// ImportScan / ReimportScan upload a scan file (multipart) via
	// /api/v2/import-scan/ and /api/v2/reimport-scan/.
	ImportScan(ctx context.Context, req ImportRequest) (*ImportResult, error)
	ReimportScan(ctx context.Context, req ImportRequest) (*ImportResult, error)

	ListFindings(ctx context.Context, q FindingQuery) (*Page[Finding], error)
	PatchFinding(ctx context.Context, id int64, p FindingPatch) (*Finding, error)
	AddFindingNote(ctx context.Context, findingID int64, text string) error

	ListAssets(ctx context.Context, q AssetQuery) (*Page[Asset], error)
	ListEngagements(ctx context.Context, q EngagementQuery) (*Page[Engagement], error)
	SetEngagementStatus(ctx context.Context, id int64, status string) error
	SetAssetTags(ctx context.Context, assetID int64, tags []string) error
}

// Page is a DRF page: {"count","next","previous","results"}.
type Page[T any] struct {
	Count   int    `json:"count"`
	Next    string `json:"next"`
	Results []T    `json:"results"`
}

type Organization struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type AssetSpec struct {
	Name           string   `json:"name"` // the IP, or "RAVEN Planning"
	Description    string   `json:"description"`
	OrganizationID int64    `json:"organization"`
	Tags           []string `json:"tags,omitempty"`
}

type Asset struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	OrganizationID int64    `json:"organization"`
	Tags           []string `json:"tags"`
}

type AssetQuery struct {
	Name           string   // exact (case-insensitive) name
	Tags           []string // any of (Dojo "tags" filter is OR)
	OrganizationID int64    // only assets of this organization
	Limit          int
	Offset         int
}

// Engagement statuses we use (Dojo ENGAGEMENT_STATUS_CHOICES).
const (
	EngagementNotStarted = "Not Started"
	EngagementInProgress = "In Progress"
	EngagementCompleted  = "Completed"
)

type EngagementSpec struct {
	AssetID int64
	Name    string // "RAVEN: <profile name>"
	Tags    []string
}

type Engagement struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	AssetID     int64     `json:"product"`
	Status      string    `json:"status"` // "Not Started", "In Progress", "Completed", …
	TargetStart string    `json:"target_start"`
	TargetEnd   string    `json:"target_end"`
	Tags        []string  `json:"tags"`
	Updated     time.Time `json:"updated"`
}

type EngagementQuery struct {
	AssetID     int64
	Name        string
	Status      string
	Tags        []string // exact tags (OR)
	TagContains string   // substring match on tag name (Dojo "tag" icontains filter)
	Limit       int
	Offset      int
}

type TestSpec struct {
	EngagementID int64
	ScanType     string // scanner.DojoScanType(): "Nmap Scan", "Nuclei Scan"; also the Dojo test type name
	Title        string
}

type Test struct {
	ID           int64  `json:"id"`
	EngagementID int64  `json:"engagement"`
	Title        string `json:"title"`
	ScanType     string `json:"scan_type"`
}

// ImportRequest is one import-scan / reimport-scan upload. The target is
// either TestID (reimport), EngagementID (import), or the names with
// AutoCreate=true (Dojo then creates the organization/asset/engagement).
type ImportRequest struct {
	ScanType         string // Dojo parser name
	TestID           int64  // reimport target (0 = resolve by names below)
	EngagementID     int64
	AssetName        string
	OrganizationName string
	EngagementName   string
	TestTitle        string
	AutoCreate       bool // auto_create_context
	FileName         string
	File             io.Reader
	CloseOldFindings bool
	Tags             []string // test tags (reimport overwrites them)
	TagFindings      bool     // apply_tags_to_findings
	ScanDate         time.Time
}

// ImportResult is parsed from the import/reimport response. Created/Closed/
// Reactivated/Untouched come from statistics.delta, which only reimport into
// an existing test returns; for a fresh import Created = all findings.
type ImportResult struct {
	TestID         int64
	EngagementID   int64
	AssetID        int64
	OrganizationID int64
	Created        int
	Closed         int
	Reactivated    int
	Untouched      int
	Active         int // active findings in the test after the import
	Total          int // all findings in the test after the import
}

type Finding struct {
	ID               int64     `json:"id"`
	Title            string    `json:"title"`
	Severity         string    `json:"severity"`
	Active           bool      `json:"active"`
	Verified         bool      `json:"verified"`
	FalseP           bool      `json:"false_p"`
	RiskAccepted     bool      `json:"risk_accepted"`
	IsMitigated      bool      `json:"is_mitigated"`
	Tags             []string  `json:"tags"`
	Test             int64     `json:"test"`
	Date             string    `json:"date"`
	LastStatusUpdate time.Time `json:"last_status_update"`
	TestTypeName     string    `json:"test_type_name"` // scan type of the test, e.g. "Nmap Scan"
	UniqueIDFromTool string    `json:"unique_id_from_tool"`

	// RelatedFields is only filled when FindingQuery.Related is set.
	RelatedFields *FindingRelated `json:"related_fields"`
}

// FindingRelated is Dojo's related_fields=true block: test → engagement → asset.
type FindingRelated struct {
	Test *struct {
		ID         int64 `json:"id"`
		Engagement *struct {
			ID      int64 `json:"id"`
			Product *struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"product"`
		} `json:"engagement"`
	} `json:"test"`
}

// Asset returns the finding's asset id and name from RelatedFields (0, "" if absent).
func (f *Finding) Asset() (int64, string) {
	r := f.RelatedFields
	if r == nil || r.Test == nil || r.Test.Engagement == nil || r.Test.Engagement.Product == nil {
		return 0, ""
	}
	return r.Test.Engagement.Product.ID, r.Test.Engagement.Product.Name
}

type FindingQuery struct {
	Tags             []string // any of (Dojo "tags" filter is OR)
	TestID           int64
	AssetID          int64
	UniqueIDFromTool string // substring match
	OrganizationID   int64  // only findings of assets in this organization
	Active           *bool
	Related          bool // ask for related_fields (test → engagement → asset)
	Limit            int
	Offset           int
}

// FindingPatch holds the triage fields our UI can change (nil = unchanged).
type FindingPatch struct {
	Severity     *string `json:"severity,omitempty"`
	Active       *bool   `json:"active,omitempty"`
	Verified     *bool   `json:"verified,omitempty"`
	FalseP       *bool   `json:"false_p,omitempty"`
	RiskAccepted *bool   `json:"risk_accepted,omitempty"`
	IsMitigated  *bool   `json:"is_mitigated,omitempty"`
}
