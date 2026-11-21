// Package exchange implements import and export of targets and scan results
// (architecture §7, task P3): our JSON/CSV formats, raw nmap XML, nuclei
// JSONL, Nessus .nessus reports, and filtered JSON/CSV exports.
package exchange

import (
	"bytes"
	"errors"
	"strings"
)

var (
	ErrInvalid  = errors.New("invalid import/export request")
	ErrNotFound = errors.New("not found")
	ErrNotReady = errors.New("dojo not ready")
)

// MaxImportBytes caps uploaded result files (25 MiB).
const MaxImportBytes = 25 << 20

// MaxExportRows caps the number of rows returned by a single export request.
const MaxExportRows = 100000

// ImportKind selects the parser for POST /api/import/results.
type ImportKind string

const (
	ImportResultsJSON ImportKind = "results-json"
	ImportResultsCSV  ImportKind = "results-csv"
	ImportNmapXML     ImportKind = "nmap-xml"
	ImportNucleiJSONL ImportKind = "nuclei-jsonl"
	ImportNessus      ImportKind = "nessus"
)

// ValidImportKind reports whether k is a supported result import kind.
func ValidImportKind(k ImportKind) bool {
	switch k {
	case ImportResultsJSON, ImportResultsCSV, ImportNmapXML, ImportNucleiJSONL, ImportNessus:
		return true
	default:
		return false
	}
}

// DetectImportKind guesses the import kind from the filename extension or
// leading bytes when the caller omits the kind field.
func DetectImportKind(filename string, raw []byte) ImportKind {
	name := strings.ToLower(strings.TrimSpace(filename))
	switch {
	case strings.HasSuffix(name, ".nessus"):
		return ImportNessus
	case strings.HasSuffix(name, ".xml"):
		if bytes.Contains(raw[:min(len(raw), 4096)], []byte("<NessusClientData_v2")) {
			return ImportNessus
		}
		return ImportNmapXML
	case strings.HasSuffix(name, ".jsonl"), strings.HasSuffix(name, ".ndjson"):
		return ImportNucleiJSONL
	case strings.HasSuffix(name, ".csv"):
		return ImportResultsCSV
	case strings.HasSuffix(name, ".json"):
		return ImportResultsJSON
	}

	head := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\ufeff")))
	switch {
	case bytes.Contains(head[:min(len(head), 4096)], []byte("<NessusClientData_v2")):
		return ImportNessus
	case bytes.HasPrefix(head, []byte("<")):
		return ImportNmapXML
	case bytes.HasPrefix(head, []byte("{")):
		// Distinguish nuclei JSONL (multiple JSON objects per line with template-id)
		// from our results JSON object.
		if bytes.Contains(head[:min(len(head), 2048)], []byte(`"template-id"`)) {
			return ImportNucleiJSONL
		}
		return ImportResultsJSON
	case bytes.HasPrefix(head, []byte("[")):
		return ImportResultsJSON
	default:
		return ImportResultsCSV
	}
}

// ExportKind selects the dataset for GET /api/export/{kind}.
type ExportKind string

const (
	KindHosts    ExportKind = "hosts"
	KindServices ExportKind = "services"
	KindFindings ExportKind = "findings"
	KindChanges  ExportKind = "changes"
	KindTargets  ExportKind = "targets"
)

// ExportFormat is json or csv.
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
)

// ValidExportFormat reports whether f is json or csv.
func ValidExportFormat(f ExportFormat) bool {
	return f == FormatJSON || f == FormatCSV
}
