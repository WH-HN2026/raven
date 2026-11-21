// Package mcp exposes RAVEN's domain services over the Model Context Protocol
// (MCP) via Streamable HTTP at /mcp, authenticated with Bearer API tokens and
// governed by the same RBAC rules as the HTTP API (architecture D10, §6, §9).
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/pipeline"
)

const (
	serverName     = "raven"
	serverVersion  = "0.1.0"
	sessionTimeout = 30 * time.Minute
	extraUserKey   = "user"
)

// Deps are the domain services backing the MCP server.
type Deps struct {
	Pool          *pgxpool.Pool
	Queries       *gen.Queries
	Tokens        auth.APITokenLookup
	Pipeline      *pipeline.Service
	DojoPublicURL string
}

// NewServer constructs an MCP server with all RAVEN read and editor tools.
func NewServer(d Deps) *sdkmcp.Server {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    serverName,
		Version: serverVersion,
	}, nil)
	registerTools(s, d)
	return s
}

// NewHandler returns an http.Handler serving Streamable HTTP MCP at /mcp
// protected by Bearer API token authentication.
func NewHandler(d Deps) http.Handler {
	srv := NewServer(d)
	streamable := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return srv
	}, &sdkmcp.StreamableHTTPOptions{
		Logger:         slog.Default(),
		SessionTimeout: sessionTimeout,
	})

	verifier := func(ctx context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		if d.Tokens == nil {
			return nil, fmt.Errorf("%w: token authentication unavailable", mcpauth.ErrInvalidToken)
		}
		u, err := d.Tokens.UserForAPIToken(ctx, token)
		if err != nil {
			slog.Error("mcp api token lookup", "err", err)
			return nil, fmt.Errorf("token lookup failed")
		}
		if u == nil {
			return nil, fmt.Errorf("%w: invalid or revoked api token", mcpauth.ErrInvalidToken)
		}
		return &mcpauth.TokenInfo{
			UserID: strconv.FormatInt(u.ID, 10),
			Extra:  map[string]any{extraUserKey: u},
		}, nil
	}

	return mcpauth.RequireBearerToken(verifier, &mcpauth.RequireBearerTokenOptions{
		AllowMissingExpiration: true,
	})(streamable)
}
