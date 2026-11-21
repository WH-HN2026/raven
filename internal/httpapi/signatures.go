package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/signatures"
)

// Custom nuclei signatures (task C2; UI is W8). Logic lives in internal/signatures.
func (a *api) mountSignatures(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/signatures", a.listSignatures)
	r.With(auth.Require(auth.PermSignaturesWrite)).Post("/signatures", a.createSignature)
	r.With(auth.Require(auth.PermSignaturesWrite)).Post("/signatures/validate", a.validateSignature)
	r.With(auth.Require(auth.PermRead)).Get("/signatures/{id}", a.getSignature)
	r.With(auth.Require(auth.PermSignaturesWrite)).Put("/signatures/{id}", a.updateSignature)
	r.With(auth.Require(auth.PermSignaturesWrite)).Delete("/signatures/{id}", a.deleteSignature)
	// TODO(S4): run one signature against one lab URL. Needs a hook from
	// internal/scanner/nuclei such as
	//   nuclei.RunTemplate(ctx, templateYAML string, url string) ([]Match, error)
	// (same safety flags as the pipeline). Answers 501 until then.
	stub(r, "POST", "/signatures/{id}/test", auth.PermSignaturesWrite)
}

func (a *api) signatureStore() *signatures.Store { return &signatures.Store{Pool: a.Pool} }

func signaturesError(w http.ResponseWriter, op string, err error) {
	var inv *signatures.InvalidError
	switch {
	case errors.As(err, &inv):
		httpx.JSON(w, http.StatusBadRequest, map[string]any{
			"error":  httpx.ErrorDetail{Code: "invalid_signature", Message: inv.Error()},
			"issues": issuesOrEmpty(inv.Issues),
		})
	case errors.Is(err, signatures.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, signatures.ErrConflict):
		httpx.Error(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, signatures.ErrBuiltin):
		httpx.Error(w, http.StatusForbidden, "builtin", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}

func issuesOrEmpty(is []signatures.Issue) []signatures.Issue {
	if is == nil {
		return []signatures.Issue{}
	}
	return is
}

func (a *api) listSignatures(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, total, err := a.signatureStore().List(r.Context(), limit, offset)
	if err != nil {
		signaturesError(w, "list signatures", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[gen.Signature]{Items: items, Total: total})
}

func (a *api) getSignature(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	sig, err := a.signatureStore().Get(r.Context(), id)
	if err != nil {
		signaturesError(w, "get signature", err)
		return
	}
	httpx.JSON(w, http.StatusOK, sig)
}

func (a *api) createSignature(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TemplateYAML string `json:"template_yaml"`
		Enabled      *bool  `json:"enabled"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	enabled := in.Enabled == nil || *in.Enabled // default: enabled when valid
	sig, err := a.signatureStore().Create(r.Context(), auth.UserFrom(r.Context()), in.TemplateYAML, enabled)
	if err != nil {
		signaturesError(w, "create signature", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, sig)
}

func (a *api) updateSignature(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		TemplateYAML *string `json:"template_yaml"`
		Enabled      *bool   `json:"enabled"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	sig, err := a.signatureStore().Update(r.Context(), auth.UserFrom(r.Context()), id,
		signatures.Update{TemplateYAML: in.TemplateYAML, Enabled: in.Enabled})
	if err != nil {
		signaturesError(w, "update signature", err)
		return
	}
	httpx.JSON(w, http.StatusOK, sig)
}

func (a *api) deleteSignature(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.signatureStore().Delete(r.Context(), auth.UserFrom(r.Context()), id); err != nil {
		signaturesError(w, "delete signature", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateSignature checks a template without saving (no audit: nothing changes).
func (a *api) validateSignature(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TemplateYAML string `json:"template_yaml"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	tpl, issues := signatures.Validate([]byte(in.TemplateYAML))
	msgs := make([]string, len(issues))
	for i, is := range issues {
		msgs[i] = is.String()
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"valid": len(issues) == 0, "errors": msgs, "issues": issuesOrEmpty(issues),
		"id": tpl.ID, "name": tpl.Name, "severity": tpl.Severity, "tags": append([]string{}, tpl.Tags...),
	})
}
