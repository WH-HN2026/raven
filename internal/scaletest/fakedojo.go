//go:build scaletest

package scaletest

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// FakeDojoStats summarizes requests handled by the local httptest Dojo stub.
type FakeDojoStats struct {
	TotalRequests      int64
	AssetsCreated      int64
	EngagementsCreated int64
	TestsCreated       int64
	ReimportCalls      int64
	ReimportByType     map[string]int64
	BytesUploaded      int64
}

// FakeDojo is an in-process httptest.Server stub of DefectDojo 3.5 API v2.
// It accepts all endpoints used by dojo.Pusher / dojo.PushService, stores
// only lightweight ID maps (never uploaded payloads), and counts calls so
// scale tests never touch the shared DefectDojo instance.
type FakeDojo struct {
	Server *httptest.Server

	totalReqs          atomic.Int64
	assetsCreated      atomic.Int64
	engagementsCreated atomic.Int64
	testsCreated       atomic.Int64
	reimportCalls      atomic.Int64
	bytesUploaded      atomic.Int64

	mu           sync.Mutex
	nextID       int64
	orgs         map[string]int64
	assetsByName map[string]*stubAsset
	assetsByID   map[int64]*stubAsset
	engsByKey    map[string]*stubEng
	testsByKey   map[string]*stubTest
	testTypes    map[string]int64
	reimportType map[string]int64
}

type stubAsset struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	OrganizationID int64    `json:"organization"`
	Tags           []string `json:"tags"`
}

type stubEng struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	AssetID int64    `json:"product"`
	Status  string   `json:"status"`
	Tags    []string `json:"tags"`
}

type stubTest struct {
	ID           int64  `json:"id"`
	EngagementID int64  `json:"engagement"`
	Title        string `json:"title"`
	ScanType     string `json:"scan_type"`
}

// NewFakeDojo starts a loopback-only httptest.Server emulating DefectDojo v2.
func NewFakeDojo() *FakeDojo {
	d := &FakeDojo{
		nextID:       100,
		orgs:         map[string]int64{"RAVEN": 1},
		assetsByName: make(map[string]*stubAsset),
		assetsByID:   make(map[int64]*stubAsset),
		engsByKey:    make(map[string]*stubEng),
		testsByKey:   make(map[string]*stubTest),
		testTypes: map[string]int64{
			"Nmap Scan":               1,
			"httpx Scan":              2,
			"Nuclei Scan":             3,
			"Generic Findings Import": 4,
			"Tenable Scan":            5,
		},
		reimportType: make(map[string]int64),
	}
	d.Server = httptest.NewServer(http.HandlerFunc(d.serveHTTP))
	return d
}

func (d *FakeDojo) Close() { d.Server.Close() }

func (d *FakeDojo) Stats() FakeDojoStats {
	d.mu.Lock()
	byType := make(map[string]int64, len(d.reimportType))
	for k, v := range d.reimportType {
		byType[k] = v
	}
	d.mu.Unlock()
	return FakeDojoStats{
		TotalRequests:      d.totalReqs.Load(),
		AssetsCreated:      d.assetsCreated.Load(),
		EngagementsCreated: d.engagementsCreated.Load(),
		TestsCreated:       d.testsCreated.Load(),
		ReimportCalls:      d.reimportCalls.Load(),
		ReimportByType:     byType,
		BytesUploaded:      d.bytesUploaded.Load(),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *FakeDojo) serveHTTP(w http.ResponseWriter, r *http.Request) {
	d.totalReqs.Add(1)
	p := r.URL.Path
	switch {
	case p == "/api/v2/organizations/":
		d.handleOrgs(w, r)
	case p == "/api/v2/assets/":
		d.handleAssets(w, r)
	case strings.HasPrefix(p, "/api/v2/assets/"):
		d.handleAssetPatch(w, r)
	case p == "/api/v2/engagements/":
		d.handleEngagements(w, r)
	case p == "/api/v2/tests/":
		d.handleTests(w, r)
	case p == "/api/v2/test_types/":
		d.handleTestTypes(w, r)
	case p == "/api/v2/reimport-scan/" || p == "/api/v2/import-scan/":
		d.handleReimport(w, r)
	case p == "/api/v2/findings/":
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "next": "", "results": []any{}})
	default:
		http.NotFound(w, r)
	}
}

func (d *FakeDojo) handleOrgs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		name := r.URL.Query().Get("name")
		d.mu.Lock()
		id, ok := d.orgs[name]
		d.mu.Unlock()
		if ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"count": 1, "results": []map[string]any{{"id": id, "name": name}},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []any{}})
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	d.mu.Lock()
	id, ok := d.orgs[in.Name]
	if !ok {
		d.nextID++
		id = d.nextID
		d.orgs[in.Name] = id
	}
	d.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": in.Name})
}

func (d *FakeDojo) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		name := r.URL.Query().Get("name_exact")
		d.mu.Lock()
		a := d.assetsByName[name]
		d.mu.Unlock()
		if a != nil {
			writeJSON(w, http.StatusOK, map[string]any{"count": 1, "results": []*stubAsset{a}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []any{}})
		return
	}
	var in stubAsset
	_ = json.NewDecoder(r.Body).Decode(&in)
	d.mu.Lock()
	if existing := d.assetsByName[in.Name]; existing != nil {
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, existing)
		return
	}
	d.nextID++
	in.ID = d.nextID
	if in.Tags == nil {
		in.Tags = []string{}
	}
	cp := in
	d.assetsByName[in.Name] = &cp
	d.assetsByID[in.ID] = &cp
	d.mu.Unlock()
	d.assetsCreated.Add(1)
	writeJSON(w, http.StatusCreated, &cp)
}

func (d *FakeDojo) handleAssetPatch(w http.ResponseWriter, r *http.Request) {
	idStr := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/assets/"), "/")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	var in struct {
		Tags []string `json:"tags"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	d.mu.Lock()
	if a := d.assetsByID[id]; a != nil && in.Tags != nil {
		a.Tags = append([]string(nil), in.Tags...)
	}
	a := d.assetsByID[id]
	d.mu.Unlock()
	if a == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (d *FakeDojo) handleEngagements(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		prod := r.URL.Query().Get("product")
		name := r.URL.Query().Get("name")
		key := prod + "|" + name
		d.mu.Lock()
		e := d.engsByKey[key]
		d.mu.Unlock()
		if e != nil {
			writeJSON(w, http.StatusOK, map[string]any{"count": 1, "results": []*stubEng{e}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []any{}})
		return
	}
	var in stubEng
	_ = json.NewDecoder(r.Body).Decode(&in)
	key := strconv.FormatInt(in.AssetID, 10) + "|" + in.Name
	d.mu.Lock()
	if existing := d.engsByKey[key]; existing != nil {
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, existing)
		return
	}
	d.nextID++
	in.ID = d.nextID
	cp := in
	d.engsByKey[key] = &cp
	d.mu.Unlock()
	d.engagementsCreated.Add(1)
	writeJSON(w, http.StatusCreated, &cp)
}

func (d *FakeDojo) handleTests(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		eng := r.URL.Query().Get("engagement")
		st := r.URL.Query().Get("scan_type")
		title := r.URL.Query().Get("title")
		key := eng + "|" + st + "|" + title
		d.mu.Lock()
		t := d.testsByKey[key]
		d.mu.Unlock()
		if t != nil {
			writeJSON(w, http.StatusOK, map[string]any{"count": 1, "results": []*stubTest{t}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []any{}})
		return
	}
	var in stubTest
	_ = json.NewDecoder(r.Body).Decode(&in)
	key := strconv.FormatInt(in.EngagementID, 10) + "|" + in.ScanType + "|" + in.Title
	d.mu.Lock()
	if existing := d.testsByKey[key]; existing != nil {
		d.mu.Unlock()
		writeJSON(w, http.StatusOK, existing)
		return
	}
	d.nextID++
	in.ID = d.nextID
	cp := in
	d.testsByKey[key] = &cp
	d.mu.Unlock()
	d.testsCreated.Add(1)
	writeJSON(w, http.StatusCreated, &cp)
}

func (d *FakeDojo) handleTestTypes(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	d.mu.Lock()
	id, ok := d.testTypes[name]
	d.mu.Unlock()
	if ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"count": 1, "results": []map[string]any{{"id": id, "name": name}},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []any{}})
}

func (d *FakeDojo) handleReimport(w http.ResponseWriter, r *http.Request) {
	var scanType string
	var testID int64
	var nBytes int64
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && params["boundary"] != "" {
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			switch part.FormName() {
			case "scan_type":
				b, _ := io.ReadAll(io.LimitReader(part, 128))
				scanType = string(b)
			case "test":
				b, _ := io.ReadAll(io.LimitReader(part, 64))
				testID, _ = strconv.ParseInt(string(b), 10, 64)
			default:
				n, _ := io.Copy(io.Discard, part)
				nBytes += n
			}
			_ = part.Close()
		}
	} else {
		nBytes, _ = io.Copy(io.Discard, r.Body)
	}
	d.reimportCalls.Add(1)
	d.bytesUploaded.Add(nBytes)
	if scanType != "" {
		d.mu.Lock()
		d.reimportType[scanType]++
		d.mu.Unlock()
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"test_id": testID,
		"statistics": map[string]any{
			"after": map[string]any{"total": map[string]any{"active": 1, "total": 1}},
		},
	})
}
