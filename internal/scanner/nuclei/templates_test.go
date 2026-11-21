package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/WH-HN2026/raven/internal/signatures"
)

func TestCustomTemplates(t *testing.T) {
	pack, err := signatures.Pack()
	if err != nil || len(pack) == 0 {
		t.Fatalf("read C2 pack: %v", err)
	}
	tpl, issues := signatures.Validate([]byte(pack[0].YAML))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	s := &Scanner{CustomDir: filepath.Join(t.TempDir(), "optional")}
	if paths, err := s.customTemplates(context.Background(), t.TempDir(), nil); err != nil || len(paths) != 0 {
		t.Fatalf("missing directory returned %v, %v", paths, err)
	}
	if err := os.Mkdir(s.CustomDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.CustomDir, "signature.yaml")
	if err := os.WriteFile(path, []byte(pack[0].YAML), 0600); err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	paths, err := s.customTemplates(context.Background(), staging, nil)
	if err != nil || !slices.Equal(paths, []string{"custom"}) {
		t.Fatalf("optional directory returned %v, %v", paths, err)
	}
	got, err := os.ReadFile(filepath.Join(staging, paths[0], tpl.ID+".yaml"))
	if err != nil || string(got) != pack[0].YAML {
		t.Fatalf("read staged signature: %v", err)
	}
	if err := os.WriteFile(path, []byte(pack[0].YAML+"\n---\n"+pack[0].YAML), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.customTemplates(context.Background(), t.TempDir(), nil); err == nil {
		t.Fatal("accepted a second YAML document")
	}
}

func TestOfficialTemplatesRejectChangedContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, official[0].path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("modified template"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{TemplatesDir: root}
	if _, _, err := s.officialTemplates(t.TempDir(), []string{"tech"}, false); err == nil {
		t.Fatal("accepted a changed official template")
	}
}
