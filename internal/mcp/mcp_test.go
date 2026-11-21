package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/WH-HN2026/raven/internal/auth"
)

type stubTokens map[string]*auth.User

func (s stubTokens) UserForAPIToken(_ context.Context, token string) (*auth.User, error) {
	return s[token], nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if t.token != "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(clone)
}

func connectTestClient(t *testing.T, endpoint, token string) *sdkmcp.ClientSession {
	t.Helper()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	tr := &sdkmcp.StreamableClientTransport{
		Endpoint: endpoint,
		HTTPClient: &http.Client{
			Transport: &bearerTransport{base: http.DefaultTransport, token: token},
		},
	}
	sess, err := client.Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func TestHandlerAuth(t *testing.T) {
	tokens := stubTokens{
		"valid-viewer": {ID: 2, Username: "vi", Role: auth.RoleViewer},
	}
	h := NewHandler(Deps{Tokens: tokens})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Unauthenticated / invalid tokens must get HTTP 401.
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"missing header", ""},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"unknown token", "Bearer nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("got status %d, want 401", resp.StatusCode)
			}
		})
	}

	// Valid bearer token connects and lists all 7 tools.
	sess := connectTestClient(t, srv.URL, "valid-viewer")
	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	want := []string{"add_targets", "get_changes", "get_host", "list_findings", "list_runs", "search_hosts", "start_scan"}
	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v, want %v", names, want)
	}
}

func TestToolRBACAndValidation(t *testing.T) {
	tokens := stubTokens{
		"tok-viewer":   {ID: 2, Username: "vi", Role: auth.RoleViewer},
		"tok-operator": {ID: 3, Username: "op", Role: auth.RoleOperator},
		"tok-editor":   {ID: 4, Username: "ed", Role: auth.RoleEditor},
	}
	srv := httptest.NewServer(NewHandler(Deps{Tokens: tokens}))
	t.Cleanup(srv.Close)

	ctx := context.Background()

	// Viewer and operator cannot call editor tools.
	for _, tok := range []string{"tok-viewer", "tok-operator"} {
		sess := connectTestClient(t, srv.URL, tok)
		for _, tc := range []struct {
			tool string
			args map[string]any
			perm string
		}{
			{"start_scan", map[string]any{"profile_id": 1}, "runs:control"},
			{"add_targets", map[string]any{"targets": []map[string]any{{"value": "172.30.0.10"}}}, "targets:write"},
		} {
			res, err := sess.CallTool(ctx, &sdkmcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
			if err != nil {
				t.Fatalf("%s/%s protocol error: %v", tok, tc.tool, err)
			}
			if !res.IsError {
				t.Fatalf("%s/%s: expected IsError=true", tok, tc.tool)
			}
			txt := toolText(res)
			if !strings.Contains(txt, "permission denied") || !strings.Contains(txt, tc.perm) {
				t.Fatalf("%s/%s error = %q, want permission denied for %s", tok, tc.tool, txt, tc.perm)
			}
		}
	}

	// Input validation rejects bad arguments with IsError before touching DB.
	viewerSess := connectTestClient(t, srv.URL, "tok-viewer")
	for _, tc := range []struct {
		name string
		tool string
		args map[string]any
		want string
	}{
		{"invalid ip", "get_host", map[string]any{"ip": "not-an-ip"}, "database is not configured"},
		{"invalid profile_id", "list_runs", map[string]any{"profile_id": 0}, "scan pipeline is not running"},
	} {
		res, err := viewerSess.CallTool(ctx, &sdkmcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatalf("%s: unexpected protocol error: %v", tc.name, err)
		}
		if !res.IsError || !strings.Contains(toolText(res), tc.want) {
			t.Fatalf("%s: got IsError=%v text=%q, want containing %q", tc.name, res.IsError, toolText(res), tc.want)
		}
	}
}

func toolText(res *sdkmcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
