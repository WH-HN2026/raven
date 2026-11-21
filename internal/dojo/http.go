package dojo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is the concrete API v2 client. M0 implements only what startup
// needs (token, organization, asset); D1 adds the rest of Client.
type HTTPClient struct {
	base  string // e.g. http://nginx:8080
	token string
	hc    *http.Client
}

func NewHTTPClient(baseURL, token string) *HTTPClient {
	return &HTTPClient{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{Timeout: 60 * time.Second},
	}
}

// ObtainToken exchanges admin credentials for the user's API token
// (POST /api/v2/api-token-auth/).
func ObtainToken(ctx context.Context, baseURL, user, password string) (string, error) {
	c := NewHTTPClient(baseURL, "")
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

func (c *HTTPClient) GetOrCreateOrganization(ctx context.Context, name string) (*Organization, error) {
	var page Page[Organization]
	if err := c.do(ctx, http.MethodGet, "/api/v2/organizations/", url.Values{"name": {name}}, nil, &page); err != nil {
		return nil, fmt.Errorf("dojo list organizations %q: %w", name, err)
	}
	for _, o := range page.Results {
		if o.Name == name {
			return &o, nil
		}
	}
	var o Organization
	if err := c.do(ctx, http.MethodPost, "/api/v2/organizations/", nil,
		map[string]any{"name": name, "description": "Created by ASI"}, &o); err != nil {
		return nil, fmt.Errorf("dojo create organization %q: %w", name, err)
	}
	return &o, nil
}

func (c *HTTPClient) GetOrCreateAsset(ctx context.Context, a AssetSpec) (*Asset, error) {
	var page Page[Asset]
	if err := c.do(ctx, http.MethodGet, "/api/v2/assets/", url.Values{"name_exact": {a.Name}}, nil, &page); err != nil {
		return nil, fmt.Errorf("dojo list assets %q: %w", a.Name, err)
	}
	for _, x := range page.Results {
		if x.Name == a.Name {
			return &x, nil
		}
	}
	var out Asset
	if err := c.do(ctx, http.MethodPost, "/api/v2/assets/", nil, a, &out); err != nil {
		return nil, fmt.Errorf("dojo create asset %q: %w", a.Name, err)
	}
	return &out, nil
}

// do sends a JSON request and decodes a JSON response into out (if non-nil).
func (c *HTTPClient) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Token "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if strings.Contains(resp.Header.Get("Content-Type"), "html") {
			msg = []byte("(html error page)") // e.g. nginx 502 while Dojo boots
		}
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s %s: decode: %w", method, path, err)
	}
	return nil
}
