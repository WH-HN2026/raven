package httpapi

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/exchange"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/pipeline"
)

// Import / export (task P3). Logic lives in internal/exchange.
func (a *api) mountExchange(r chi.Router) {
	r.With(auth.Require(auth.PermImport)).Post("/import/results", a.importResults)
	r.With(auth.Require(auth.PermExport)).Get("/export/{kind}", a.exportData)
}

func (a *api) exchangeService() *exchange.Service {
	return &exchange.Service{
		Pool:          a.Pool,
		Pipeline:      a.Pipeline,
		DojoPush:      a.DojoPush,
		DojoPublicURL: a.DojoPublicURL,
	}
}

func (a *api) importResults(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, exchange.MaxImportBytes+128<<10)
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			httpx.Error(w, http.StatusRequestEntityTooLarge, "too_large", "upload is larger than 25 MiB")
			return
		}
		httpx.Error(w, http.StatusBadRequest, "bad_request", "multipart form required: "+err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}

	f, hdr, err := r.FormFile("file")
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "multipart field \"file\" is required: "+err.Error())
		return
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, exchange.MaxImportBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			httpx.Error(w, http.StatusRequestEntityTooLarge, "too_large", "upload is larger than 25 MiB")
			return
		}
		httpx.Error(w, http.StatusBadRequest, "bad_request", "read upload: "+err.Error())
		return
	}
	if len(data) > exchange.MaxImportBytes {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "too_large", "upload is larger than 25 MiB")
		return
	}

	kind := exchange.ImportKind(strings.ToLower(strings.TrimSpace(
		cmp.Or(r.FormValue("kind"), r.URL.Query().Get("kind")),
	)))
	profile := strings.TrimSpace(cmp.Or(
		r.FormValue("profile"),
		r.FormValue("profile_id"),
		r.URL.Query().Get("profile"),
		r.URL.Query().Get("profile_id"),
	))

	run, err := a.exchangeService().ImportResults(r.Context(), auth.UserFrom(r.Context()), exchange.ImportRequest{
		Kind:     kind,
		Profile:  profile,
		Filename: hdr.Filename,
		Data:     data,
	})
	if err != nil {
		exchangeError(w, "import results", err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, run)
}

func (a *api) exportData(w http.ResponseWriter, r *http.Request) {
	kind := exchange.ExportKind(strings.ToLower(strings.TrimSpace(chi.URLParam(r, "kind"))))
	format := exchange.ExportFormat(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))))
	if format == "" {
		format = exchange.FormatJSON
	}
	if !exchange.ValidExportFormat(format) {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "format must be json or csv")
		return
	}

	var buf bytes.Buffer
	var err error
	switch kind {
	case exchange.KindHosts:
		f, msg := parseHostFilter(r)
		if msg != "" {
			httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
			return
		}
		err = exchange.ExportHosts(r.Context(), a.Pool, f, format, &buf)

	case exchange.KindServices:
		f, msg := parseServiceFilter(r)
		if msg != "" {
			httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
			return
		}
		err = exchange.ExportServices(r.Context(), a.Pool, f, format, &buf)

	case exchange.KindFindings:
		f, msg := parseFindingFilter(r)
		if msg != "" {
			httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
			return
		}
		err = exchange.ExportFindings(r.Context(), a.Pool, f, a.DojoPublicURL, format, &buf)

	case exchange.KindChanges:
		from, ok1 := changesRunParam(w, r, "from")
		if !ok1 {
			return
		}
		to, ok2 := changesRunParam(w, r, "to")
		if !ok2 {
			return
		}
		limit, ok := changesIntParam(w, r, "limit", 5000, 1, 50000)
		if !ok {
			return
		}
		err = exchange.ExportChanges(r.Context(), a.Queries, from, to, limit, format, &buf)

	case exchange.KindTargets:
		err = exchange.ExportTargets(r.Context(), a.Pool, format, &buf)

	default:
		httpx.Error(w, http.StatusBadRequest, "bad_request", "kind must be one of hosts, services, findings, changes, targets")
		return
	}

	if err != nil {
		exchangeError(w, "export "+string(kind), err)
		return
	}

	if format == exchange.FormatCSV {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="raven-`+string(kind)+`.`+string(format)+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func parseServiceFilter(r *http.Request) (exchange.ServiceFilter, string) {
	var f exchange.ServiceFilter
	qs := r.URL.Query()
	if v := strings.TrimSpace(qs.Get("port")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return f, "port must be 0..65535"
		}
		f.Port = &n
	}
	if v := strings.ToLower(strings.TrimSpace(cmp.Or(qs.Get("proto"), qs.Get("protocol")))); v != "" {
		if v != "tcp" && v != "udp" {
			return f, "proto must be tcp or udp"
		}
		f.Proto = v
	}
	if v := strings.ToLower(strings.TrimSpace(qs.Get("state"))); v != "" {
		if v != "open" && v != "gone" {
			return f, "state must be open or gone"
		}
		f.State = v
	}
	if v := strings.TrimSpace(qs.Get("ip")); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			addr, aerr := netip.ParseAddr(v)
			if aerr != nil {
				return f, "ip must be an IP address or CIDR"
			}
			addr = addr.Unmap()
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		f.IP = &p
	}
	f.Product = strings.TrimSpace(qs.Get("product"))
	f.Technology = strings.TrimSpace(cmp.Or(qs.Get("technology"), qs.Get("tech")))
	f.Version = strings.TrimSpace(qs.Get("version"))
	f.Q = strings.TrimSpace(qs.Get("q"))
	return f, ""
}

func exchangeError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, exchange.ErrInvalid), errors.Is(err, pipeline.ErrInvalid), errors.Is(err, changes.ErrSameRun):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, exchange.ErrNotFound), errors.Is(err, pipeline.ErrNotFound),
		errors.Is(err, changes.ErrRunNotFound), errors.Is(err, changes.ErrNoRuns):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, exchange.ErrNotReady):
		httpx.Error(w, http.StatusServiceUnavailable, "not_ready", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}
