// Command gen regenerates internal/cve/data/cve.json.gz (run via `make cve-db`
// on a dev machine; never at build or run time). It only downloads public
// data and never sends anything of ours:
//   - NVD CVE 2.0 for every NVD vendor:product in products.txt (no API key →
//     one request per 6 s, as NVD asks; set NVD_API_KEY for faster runs);
//   - CISA KEV (known exploited vulnerabilities);
//   - FIRST EPSS scores.
//
// Only the fields the matcher needs are kept: id, score/severity, published,
// the product's version ranges, KEV and EPSS.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/cve"
)

const (
	nvdURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	perPage = 2000
)

func main() {
	products := flag.String("products", "internal/cve/products.txt", "curated product list")
	out := flag.String("out", "internal/cve/"+cve.DataFile, "output gzip JSON")
	only := flag.String("only", "", "comma-separated vendor:product subset (for testing the generator)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, *products, *out, *only); err != nil {
		log.Fatal(err)
	}
}

type fetcher struct {
	c     *http.Client
	key   string
	delay time.Duration
	last  time.Time
}

func run(ctx context.Context, productsPath, outPath, only string) error {
	b, err := os.ReadFile(productsPath)
	if err != nil {
		return err
	}
	prods, err := cve.ParseProducts(b)
	if err != nil {
		return err
	}
	f := &fetcher{c: &http.Client{Timeout: 2 * time.Minute}, key: os.Getenv("NVD_API_KEY"), delay: 6500 * time.Millisecond}
	if f.key != "" {
		f.delay = 700 * time.Millisecond
	}
	db := &cve.DB{Generated: time.Now().UTC().Format(time.RFC3339), CVEs: map[string]cve.Record{}, Products: map[string][]cve.Affect{}}
	var empty []string
	for _, p := range prods {
		for _, name := range p.NVD {
			if only != "" && !slices.Contains(strings.Split(only, ","), name) {
				continue
			}
			n, err := f.product(ctx, db, name)
			if err != nil {
				return fmt.Errorf("nvd %s: %w", name, err)
			}
			log.Printf("%-55s %4d CVEs", name, n)
			if n == 0 {
				empty = append(empty, name)
			}
		}
	}
	if err := f.kev(ctx, db); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	if err := f.epss(ctx, db); err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	if len(empty) > 0 {
		log.Printf("no CVEs with version ranges for: %s", strings.Join(empty, " "))
	}
	return write(outPath, db)
}

func write(path string, db *cve.DB) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(fh, gzip.BestCompression)
	if err := json.NewEncoder(zw).Encode(db); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	st, _ := os.Stat(path)
	log.Printf("wrote %s: %d CVEs, %d products, %d bytes", path, len(db.CVEs), len(db.Products), st.Size())
	return nil
}

// get fetches one URL, spacing requests by f.delay and retrying throttling.
func (f *fetcher) get(ctx context.Context, u string, auth bool) (io.ReadCloser, error) {
	for attempt := 1; ; attempt++ {
		if wait := f.delay - time.Since(f.last); auth && wait > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "asi-cve-db/1")
		if auth && f.key != "" {
			req.Header.Set("apiKey", f.key)
		}
		if auth {
			f.last = time.Now()
		}
		resp, err := f.c.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		if err == nil {
			resp.Body.Close()
			err = fmt.Errorf("GET %s: %s", u, resp.Status)
			if resp.StatusCode == http.StatusNotFound {
				return nil, err
			}
		}
		if attempt >= 6 {
			return nil, err
		}
		log.Printf("retry in %ds: %v", 15*attempt, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(15*attempt) * time.Second):
		}
	}
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID         string `json:"id"`
			Published  string `json:"published"`
			VulnStatus string `json:"vulnStatus"`
			Metrics    struct {
				V40 []nvdMetric `json:"cvssMetricV40"`
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
						SI         string `json:"versionStartIncluding"`
						SE         string `json:"versionStartExcluding"`
						EI         string `json:"versionEndIncluding"`
						EE         string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Type     string `json:"type"` // Primary | Secondary
	BaseSev  string `json:"baseSeverity"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// score picks the primary metric of the newest CVSS 3.x, then 4.0, then 2.
func score(lists ...[]nvdMetric) (float64, string) {
	for _, l := range lists {
		if len(l) == 0 {
			continue
		}
		m := l[0]
		for _, x := range l {
			if x.Type == "Primary" {
				m = x
				break
			}
		}
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSev
		}
		return m.CVSSData.BaseScore, sev
	}
	return 0, ""
}

// product adds the CVEs of one vendor:product. NVD files appliance firmware
// as operating systems ("o") and most of it also has a few "a" entries, so
// firmware is fetched under both; other products under "a", falling back to
// "o" if NVD has nothing there.
func (f *fetcher) product(ctx context.Context, db *cve.DB, name string) (int, error) {
	n, err := f.productPart(ctx, db, "a", name)
	if err != nil || (n > 0 && !firmware[name]) {
		return n, err
	}
	m, err := f.productPart(ctx, db, "o", name)
	return max(n, m), err
}

// firmware are the products.txt names NVD files mostly under part "o".
var firmware = map[string]bool{
	"fortinet:fortios": true, "mikrotik:routeros": true, "cisco:ios_xe": true, "sonicwall:sonicos": true,
	"paloaltonetworks:pan-os": true, "synology:diskstation_manager": true, "qnap:qts": true,
	"citrix:application_delivery_controller_firmware": true,
}

// productPart pages through NVD for one part:vendor:product.
func (f *fetcher) productPart(ctx context.Context, db *cve.DB, part, name string) (int, error) {
	affects := map[string][]cve.Range{}
	for start := 0; ; start += perPage {
		q := url.Values{}
		q.Set("virtualMatchString", "cpe:2.3:"+part+":"+name)
		q.Set("resultsPerPage", strconv.Itoa(perPage))
		q.Set("startIndex", strconv.Itoa(start))
		body, err := f.get(ctx, nvdURL+"?"+q.Encode(), true)
		if err != nil {
			return 0, err
		}
		var page nvdPage
		err = json.NewDecoder(body).Decode(&page)
		body.Close()
		if err != nil {
			return 0, err
		}
		for _, v := range page.Vulnerabilities {
			c := v.CVE
			if strings.EqualFold(c.VulnStatus, "Rejected") {
				continue
			}
			var ranges []cve.Range
			for _, cfg := range c.Configurations {
				for _, n := range cfg.Nodes {
					for _, m := range n.CPEMatch {
						if !m.Vulnerable {
							continue
						}
						vp, ver, ok := criteria(m.Criteria)
						if !ok || vp != name {
							continue
						}
						r := cve.Range{StartIncl: m.SI, StartExcl: m.SE, EndIncl: m.EI, EndExcl: m.EE}
						if ver != "*" && ver != "-" && ver != "" {
							r = cve.Range{Exact: ver}
						}
						if r == (cve.Range{}) || slices.Contains(ranges, r) {
							continue // "all versions" says nothing about a version
						}
						ranges = append(ranges, r)
					}
				}
			}
			if len(ranges) == 0 {
				continue
			}
			affects[c.ID] = append(affects[c.ID], ranges...)
			if _, ok := db.CVEs[c.ID]; !ok {
				s, sev := score(c.Metrics.V31, c.Metrics.V30, c.Metrics.V40, c.Metrics.V2)
				pub := c.Published
				if len(pub) >= 10 {
					pub = pub[:10]
				}
				db.CVEs[c.ID] = cve.Record{CVSS: s, Severity: strings.ToUpper(sev), Published: pub}
			}
		}
		if start+perPage >= page.TotalResults {
			break
		}
	}
	ids := make([]string, 0, len(affects))
	for id := range affects {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	have := map[string]bool{}
	for _, a := range db.Products[name] {
		have[a.ID] = true
	}
	for _, id := range ids {
		if !have[id] {
			db.Products[name] = append(db.Products[name], cve.Affect{ID: id, Ranges: affects[id]})
		}
	}
	slices.SortFunc(db.Products[name], func(a, b cve.Affect) int { return strings.Compare(a.ID, b.ID) })
	return len(ids), nil
}

// criteria splits "cpe:2.3:a:vendor:product:version:update:…" (with "\:"
// escapes) into "vendor:product" and the version; an update such as "p1"
// is appended to the version (OpenSSH "7.4" + "p1" → "7.4p1").
func criteria(c string) (vp, version string, ok bool) {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(c); i++ {
		switch {
		case c[i] == '\\' && i+1 < len(c):
			cur.WriteByte(c[i])
			cur.WriteByte(c[i+1])
			i++
		case c[i] == ':':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c[i])
		}
	}
	parts = append(parts, cur.String())
	if len(parts) < 7 || parts[0] != "cpe" {
		return "", "", false
	}
	version = strings.ReplaceAll(parts[5], `\`, "")
	if u := parts[6]; u != "*" && u != "-" && u != "" && version != "*" && version != "-" {
		version += strings.ReplaceAll(u, `\`, "")
	}
	return parts[3] + ":" + parts[4], version, true
}

func (f *fetcher) kev(ctx context.Context, db *cve.DB) error {
	body, err := f.get(ctx, kevURL, false)
	if err != nil {
		return err
	}
	defer body.Close()
	var doc struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		return err
	}
	n := 0
	for _, v := range doc.Vulnerabilities {
		if r, ok := db.CVEs[v.CVE]; ok {
			r.KEV = true
			db.CVEs[v.CVE] = r
			n++
		}
	}
	log.Printf("KEV: %d entries, %d in our data", len(doc.Vulnerabilities), n)
	if len(doc.Vulnerabilities) == 0 {
		return errors.New("empty KEV catalog")
	}
	return nil
}

func (f *fetcher) epss(ctx context.Context, db *cve.DB) error {
	body, err := f.get(ctx, epssURL, false)
	if err != nil {
		return err
	}
	defer body.Close()
	zr, err := gzip.NewReader(body)
	if err != nil {
		return err
	}
	br := bufio.NewReader(zr)
	// First line is "#model_version:…,score_date:…", then "cve,epss,percentile".
	if _, err := br.ReadString('\n'); err != nil {
		return err
	}
	r := csv.NewReader(br)
	r.FieldsPerRecord = -1
	n, total := 0, 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if len(rec) < 2 || rec[0] == "cve" {
			continue
		}
		total++
		c, ok := db.CVEs[rec[0]]
		if !ok {
			continue
		}
		if v, err := strconv.ParseFloat(rec[1], 64); err == nil {
			c.EPSS = v
			db.CVEs[rec[0]] = c
			n++
		}
	}
	log.Printf("EPSS: %d scores, %d in our data", total, n)
	if total == 0 {
		return errors.New("empty EPSS file")
	}
	return nil
}
