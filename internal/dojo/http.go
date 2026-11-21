package dojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var _ Client = (*HTTPClient)(nil)

// Options tune the transport. Zero values mean the defaults below.
type Options struct {
	Concurrency int           // max in-flight requests (default 4)
	Timeout     time.Duration // per attempt (default 2m: reimports of big hosts are slow)
	MaxAttempts int           // including the first (default 4)
	Backoff     time.Duration // first retry delay, doubled each time (default 500ms)
}

// HTTPClient is the concrete API v2 client.
type HTTPClient struct {
	base  string // e.g. http://nginx:8080
	token string
	hc    *http.Client
	opt   Options
	sem   chan struct{}
	locks [64]sync.Mutex // serialises get-or-create per name (striped)
}

func NewHTTPClient(baseURL, token string) *HTTPClient {
	return NewHTTPClientOpts(baseURL, token, Options{})
}

func NewHTTPClientOpts(baseURL, token string, o Options) *HTTPClient {
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Minute
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 4
	}
	if o.Backoff <= 0 {
		o.Backoff = 500 * time.Millisecond
	}
	return &HTTPClient{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{},
		opt:   o,
		sem:   make(chan struct{}, o.Concurrency),
	}
}

// Concurrency is the client's limit of in-flight requests.
func (c *HTTPClient) Concurrency() int { return cap(c.sem) }

// HTTPError is a non-2xx answer from Dojo. Body is truncated.
type HTTPError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// IsStatus reports whether err is an HTTPError with the given status.
func IsStatus(err error, status int) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Status == status
}

// ObtainToken exchanges admin credentials for the user's API token
// (POST /api/v2/api-token-auth/).
func ObtainToken(ctx context.Context, baseURL, user, password string) (string, error) {
	c := NewHTTPClientOpts(baseURL, "", Options{MaxAttempts: 1})
	var out struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v2/api-token-auth/", nil,
		map[string]string{"username": user, "password": password}, &out); err != nil {
		return "", fmt.Errorf("dojo token: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("dojo token: empty token in response")
	}
	return out.Token, nil
}

// lock serialises get-or-create of one object inside this process; across
// processes a duplicate create answers 400 and we re-fetch.
func (c *HTTPClient) lock(key string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	m := &c.locks[h.Sum32()%uint32(len(c.locks))]
	m.Lock()
	return m.Unlock
}

// do sends a JSON request and decodes a JSON response into out (if non-nil).
func (c *HTTPClient) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var b []byte
	ct := ""
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
		ct = "application/json"
	}
	return c.send(ctx, method, path, q, ct, b, out)
}

// send runs one logical request: it retries 5xx/429/network errors with
// exponential backoff, never 4xx, and holds a semaphore slot per attempt.
func (c *HTTPClient) send(ctx context.Context, method, path string, q url.Values, contentType string, body []byte, out any) error {
	var err error
	for attempt := 1; ; attempt++ {
		var retryAfter time.Duration
		retryAfter, err = c.attempt(ctx, method, path, q, contentType, body, out)
		if err == nil {
			return nil
		}
		var he *HTTPError
		if errors.As(err, &he) && !retryable(he.Status) {
			return err
		}
		if ctx.Err() != nil || attempt >= c.opt.MaxAttempts {
			if attempt > 1 {
				err = fmt.Errorf("after %d attempts: %w", attempt, err)
			}
			return err
		}
		wait := c.opt.Backoff << (attempt - 1)
		wait += time.Duration(rand.Int64N(int64(wait)/4 + 1)) // jitter
		if retryAfter > wait {
			wait = retryAfter
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
	}
}

func (c *HTTPClient) attempt(ctx context.Context, method, path string, q url.Values, contentType string, body []byte, out any) (time.Duration, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-c.sem }()

	ctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Token "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if strings.Contains(resp.Header.Get("Content-Type"), "html") {
			msg = []byte("(html error page)") // e.g. nginx 502 while Dojo boots
		}
		var ra time.Duration
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			ra = min(time.Duration(s)*time.Second, 30*time.Second)
		}
		return ra, &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: string(bytes.TrimSpace(msg))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return 0, fmt.Errorf("%s %s: decode: %w", method, path, err)
	}
	return 0, nil
}

// getOrCreate lists with q, returns the first result matching match, else
// creates with body. A 400 on create (the unique name was taken by a racing
// writer) triggers one re-fetch before giving up.
func getOrCreate[T any](ctx context.Context, c *HTTPClient, path string, q url.Values, match func(*T) bool, body any) (*T, error) {
	find := func() (*T, error) {
		var page Page[T]
		if err := c.do(ctx, http.MethodGet, path, q, nil, &page); err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
		for i := range page.Results {
			if match(&page.Results[i]) {
				return &page.Results[i], nil
			}
		}
		return nil, nil
	}
	if x, err := find(); err != nil || x != nil {
		return x, err
	}
	var out T
	cerr := c.do(ctx, http.MethodPost, path, nil, body, &out)
	if cerr == nil {
		return &out, nil
	}
	if IsStatus(cerr, http.StatusBadRequest) {
		if x, err := find(); err == nil && x != nil {
			return x, nil
		}
	}
	return nil, fmt.Errorf("create: %w", cerr)
}

func (c *HTTPClient) GetOrCreateOrganization(ctx context.Context, name string) (*Organization, error) {
	defer c.lock("org/" + name)()
	o, err := getOrCreate(ctx, c, "/api/v2/organizations/", url.Values{"name": {name}},
		func(o *Organization) bool { return o.Name == name },
		map[string]any{"name": name, "description": "Created by ASI"})
	if err != nil {
		return nil, fmt.Errorf("dojo organization %q: %w", name, err)
	}
	return o, nil
}

func (c *HTTPClient) GetOrCreateAsset(ctx context.Context, a AssetSpec) (*Asset, error) {
	defer c.lock("asset/" + a.Name)()
	x, err := getOrCreate(ctx, c, "/api/v2/assets/", url.Values{"name_exact": {a.Name}},
		func(x *Asset) bool { return strings.EqualFold(x.Name, a.Name) }, a)
	if err != nil {
		return nil, fmt.Errorf("dojo asset %q: %w", a.Name, err)
	}
	return x, nil
}

func (c *HTTPClient) GetOrCreateEngagement(ctx context.Context, e EngagementSpec) (*Engagement, error) {
	defer c.lock(fmt.Sprintf("eng/%d/%s", e.AssetID, e.Name))()
	today := time.Now().UTC().Format(time.DateOnly)
	body := map[string]any{
		"product":         e.AssetID,
		"name":            e.Name,
		"engagement_type": "CI/CD",
		"status":          EngagementInProgress,
		"target_start":    today,
		"target_end":      today,
		"tags":            nonNil(e.Tags),
	}
	x, err := getOrCreate(ctx, c, "/api/v2/engagements/",
		url.Values{"product": {itoa(e.AssetID)}, "name": {e.Name}},
		func(x *Engagement) bool { return x.Name == e.Name }, body)
	if err != nil {
		return nil, fmt.Errorf("dojo engagement %q (asset %d): %w", e.Name, e.AssetID, err)
	}
	return x, nil
}

func (c *HTTPClient) GetOrCreateTest(ctx context.Context, t TestSpec) (*Test, error) {
	defer c.lock(fmt.Sprintf("test/%d/%s/%s", t.EngagementID, t.ScanType, t.Title))()
	q := url.Values{"engagement": {itoa(t.EngagementID)}, "scan_type": {t.ScanType}}
	if t.Title != "" {
		q.Set("title", t.Title)
	}
	match := func(x *Test) bool { return x.ScanType == t.ScanType && x.Title == t.Title }
	var page Page[Test]
	if err := c.do(ctx, http.MethodGet, "/api/v2/tests/", q, nil, &page); err != nil {
		return nil, fmt.Errorf("dojo list tests (engagement %d): %w", t.EngagementID, err)
	}
	for i := range page.Results {
		if match(&page.Results[i]) {
			return &page.Results[i], nil
		}
	}
	// Tests have no unique key in Dojo, so the in-process lock is all the
	// race protection there is; ASI is the only writer of its tests.
	var types Page[struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}]
	if err := c.do(ctx, http.MethodGet, "/api/v2/test_types/", url.Values{"name": {t.ScanType}}, nil, &types); err != nil {
		return nil, fmt.Errorf("dojo test type %q: %w", t.ScanType, err)
	}
	if len(types.Results) == 0 {
		return nil, fmt.Errorf("dojo test type %q: not found", t.ScanType)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var out Test
	if err := c.do(ctx, http.MethodPost, "/api/v2/tests/", nil, map[string]any{
		"engagement":   t.EngagementID,
		"test_type":    types.Results[0].ID,
		"scan_type":    t.ScanType,
		"title":        t.Title,
		"target_start": now,
		"target_end":   now,
	}, &out); err != nil {
		return nil, fmt.Errorf("dojo create test %q (engagement %d): %w", t.ScanType, t.EngagementID, err)
	}
	return &out, nil
}

func (c *HTTPClient) ListFindings(ctx context.Context, q FindingQuery) (*Page[Finding], error) {
	v := pageQuery(q.Limit, q.Offset)
	if len(q.Tags) > 0 {
		v.Set("tags", strings.Join(q.Tags, ","))
	}
	if q.TestID != 0 {
		v.Set("test", itoa(q.TestID))
	}
	if q.Active != nil {
		v.Set("active", strconv.FormatBool(*q.Active))
	}
	if q.OrganizationID != 0 {
		v.Set("prod_type", itoa(q.OrganizationID))
	}
	if q.Related {
		v.Set("related_fields", "true")
	}
	v.Set("o", "id") // stable order for paging
	var page Page[Finding]
	if err := c.do(ctx, http.MethodGet, "/api/v2/findings/", v, nil, &page); err != nil {
		return nil, fmt.Errorf("dojo list findings: %w", err)
	}
	return &page, nil
}

func (c *HTTPClient) PatchFinding(ctx context.Context, id int64, p FindingPatch) (*Finding, error) {
	var out Finding
	if err := c.do(ctx, http.MethodPatch, "/api/v2/findings/"+itoa(id)+"/", nil, p, &out); err != nil {
		return nil, fmt.Errorf("dojo patch finding %d: %w", id, err)
	}
	return &out, nil
}

func (c *HTTPClient) AddFindingNote(ctx context.Context, findingID int64, text string) error {
	if err := c.do(ctx, http.MethodPost, "/api/v2/findings/"+itoa(findingID)+"/notes/", nil,
		map[string]any{"entry": text, "private": false}, nil); err != nil {
		return fmt.Errorf("dojo add note to finding %d: %w", findingID, err)
	}
	return nil
}

func (c *HTTPClient) ListAssets(ctx context.Context, q AssetQuery) (*Page[Asset], error) {
	v := pageQuery(q.Limit, q.Offset)
	if q.Name != "" {
		v.Set("name_exact", q.Name)
	}
	if len(q.Tags) > 0 {
		v.Set("tags", strings.Join(q.Tags, ","))
	}
	if q.OrganizationID != 0 {
		v.Set("organization", itoa(q.OrganizationID))
	}
	v.Set("o", "id") // stable order for paging
	var page Page[Asset]
	if err := c.do(ctx, http.MethodGet, "/api/v2/assets/", v, nil, &page); err != nil {
		return nil, fmt.Errorf("dojo list assets: %w", err)
	}
	return &page, nil
}

func (c *HTTPClient) ListEngagements(ctx context.Context, q EngagementQuery) (*Page[Engagement], error) {
	v := pageQuery(q.Limit, q.Offset)
	if q.AssetID != 0 {
		v.Set("product", itoa(q.AssetID))
	}
	if q.Name != "" {
		v.Set("name", q.Name)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if len(q.Tags) > 0 {
		v.Set("tags", strings.Join(q.Tags, ","))
	}
	if q.TagContains != "" {
		v.Set("tag", q.TagContains)
	}
	v.Set("o", "created") // stable order for paging
	var page Page[Engagement]
	if err := c.do(ctx, http.MethodGet, "/api/v2/engagements/", v, nil, &page); err != nil {
		return nil, fmt.Errorf("dojo list engagements: %w", err)
	}
	return &page, nil
}

func (c *HTTPClient) GetEngagement(ctx context.Context, id int64) (*Engagement, error) {
	var out Engagement
	if err := c.do(ctx, http.MethodGet, "/api/v2/engagements/"+itoa(id)+"/", nil, nil, &out); err != nil {
		return nil, fmt.Errorf("dojo get engagement %d: %w", id, err)
	}
	return &out, nil
}

func (c *HTTPClient) SetEngagementStatus(ctx context.Context, id int64, status string) error {
	if err := c.do(ctx, http.MethodPatch, "/api/v2/engagements/"+itoa(id)+"/", nil,
		map[string]any{"status": status}, nil); err != nil {
		return fmt.Errorf("dojo set engagement %d status %q: %w", id, status, err)
	}
	return nil
}

// SetAssetTags replaces the asset's tags.
func (c *HTTPClient) SetAssetTags(ctx context.Context, assetID int64, tags []string) error {
	if err := c.do(ctx, http.MethodPatch, "/api/v2/assets/"+itoa(assetID)+"/", nil,
		map[string]any{"tags": nonNil(tags)}, nil); err != nil {
		return fmt.Errorf("dojo set asset %d tags: %w", assetID, err)
	}
	return nil
}

func pageQuery(limit, offset int) url.Values {
	if limit <= 0 {
		limit = 100
	}
	v := url.Values{"limit": {strconv.Itoa(limit)}}
	if offset > 0 {
		v.Set("offset", strconv.Itoa(offset))
	}
	return v
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
