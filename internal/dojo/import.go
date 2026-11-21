package dojo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

// ImportScan uploads a scan into a new test (POST /api/v2/import-scan/).
func (c *HTTPClient) ImportScan(ctx context.Context, req ImportRequest) (*ImportResult, error) {
	return c.upload(ctx, "/api/v2/import-scan/", req)
}

// ReimportScan uploads a scan into an existing test (POST /api/v2/reimport-scan/);
// Dojo diffs it against the test's findings (new / closed / reactivated).
func (c *HTTPClient) ReimportScan(ctx context.Context, req ImportRequest) (*ImportResult, error) {
	return c.upload(ctx, "/api/v2/reimport-scan/", req)
}

func (c *HTTPClient) upload(ctx context.Context, path string, req ImportRequest) (*ImportResult, error) {
	body, ct, err := encodeImport(req)
	if err != nil {
		return nil, fmt.Errorf("dojo %s %q: %w", path, req.ScanType, err)
	}
	var raw importResponse
	if err := c.send(ctx, http.MethodPost, path, nil, ct, body, &raw); err != nil {
		return nil, fmt.Errorf("dojo upload %q (test %d, asset %q): %w", req.ScanType, req.TestID, req.AssetName, err)
	}
	return raw.result(), nil
}

// encodeImport builds the multipart body once, so retries can resend it.
func encodeImport(req ImportRequest) ([]byte, string, error) {
	if req.File == nil {
		return nil, "", fmt.Errorf("no file")
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	field := func(k, v string) {
		if v != "" {
			_ = w.WriteField(k, v)
		}
	}
	id := func(n int64) string {
		if n == 0 {
			return ""
		}
		return itoa(n)
	}
	field("scan_type", req.ScanType)
	field("test", id(req.TestID))
	field("engagement", id(req.EngagementID))
	field("product_name", req.AssetName)
	field("product_type_name", req.OrganizationName)
	field("engagement_name", req.EngagementName)
	field("test_title", req.TestTitle)
	field("auto_create_context", strconv.FormatBool(req.AutoCreate))
	field("close_old_findings", strconv.FormatBool(req.CloseOldFindings))
	for _, t := range req.Tags {
		field("tags", t)
	}
	field("apply_tags_to_findings", strconv.FormatBool(req.TagFindings))
	if !req.ScanDate.IsZero() {
		// Dojo rejects dates "in the future" by its own (UTC) calendar.
		field("scan_date", req.ScanDate.UTC().Format(time.DateOnly))
	}
	// Wait for dedup so the returned statistics are final.
	field("deduplication_execution_mode", "async_wait")
	name := req.FileName
	if name == "" {
		name = "scan"
	}
	fw, err := w.CreateFormFile("file", name)
	if err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(fw, req.File); err != nil {
		return nil, "", fmt.Errorf("read scan file: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// statusStats is one row of Dojo's statistics (STATS_FIELDS).
type statusStats struct {
	Active int `json:"active"`
	Total  int `json:"total"`
}

type severityStats struct {
	Total statusStats `json:"total"`
}

type importResponse struct {
	TestID        int64 `json:"test_id"`
	EngagementID  int64 `json:"engagement_id"`
	ProductID     int64 `json:"product_id"`
	ProductTypeID int64 `json:"product_type_id"`
	Statistics    struct {
		Delta *struct {
			Created     severityStats `json:"created"`
			Closed      severityStats `json:"closed"`
			Reactivated severityStats `json:"reactivated"`
			Untouched   severityStats `json:"untouched"`
		} `json:"delta"`
		After severityStats `json:"after"`
	} `json:"statistics"`
}

func (r *importResponse) result() *ImportResult {
	out := &ImportResult{
		TestID:         r.TestID,
		EngagementID:   r.EngagementID,
		AssetID:        r.ProductID,
		OrganizationID: r.ProductTypeID,
		Active:         r.Statistics.After.Total.Active,
		Total:          r.Statistics.After.Total.Total,
	}
	if d := r.Statistics.Delta; d != nil {
		out.Created = d.Created.Total.Total
		out.Closed = d.Closed.Total.Total
		out.Reactivated = d.Reactivated.Total.Total
		out.Untouched = d.Untouched.Total.Total
	} else {
		out.Created = out.Total
	}
	return out
}
