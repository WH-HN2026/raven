// Package dojo talks to DefectDojo 3.5 API v2 (D4). This file defines the
// client interface for task D1; http.go has the minimal concrete client that
// startup (bootstrap.go) needs. D1 completes HTTPClient so it implements Client.
package dojo

import (
	"context"
	"io"
	"time"
)

// Client is the DefectDojo API surface ASI uses (architecture §4).
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
	Name           string   `json:"name"` // the IP, or "ASI Planning"
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
	Tags   []string
	Limit  int
	Offset int
}

type EngagementSpec struct {
	AssetID int64
	Name    string // "ASI: <profile name>"
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
	AssetID int64
	Status  string
	Tags    []string
	Limit   int
	Offset  int
}

type TestSpec struct {
	EngagementID int64
	ScanType     string // scanner.DojoScanType(): "Nmap Scan", "Nuclei Scan"
	Title        string
}

type Test struct {
	ID           int64  `json:"id"`
	EngagementID int64  `json:"engagement"`
	Title        string `json:"title"`
	ScanType     string `json:"scan_type"`
}

type ImportRequest struct {
	ScanType         string // Dojo parser name
	TestID           int64  // reimport target (0 = resolve by names below)
	EngagementID     int64
	AssetName        string
	OrganizationName string
	EngagementName   string
	FileName         string
	File             io.Reader
	CloseOldFindings bool
	Tags             []string
	ScanDate         time.Time
}

type ImportResult struct {
	TestID        int64 `json:"test"`
	EngagementID  int64 `json:"engagement_id"`
	AssetID       int64 `json:"product_id"`
	FindingsNew   int   `json:"-"`
	FindingsClose int   `json:"-"`
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
}

type FindingQuery struct {
	Tags   []string
	Limit  int
	Offset int
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
