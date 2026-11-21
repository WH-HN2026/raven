package nuclei

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/WH-HN2026/raven/internal/signatures"
)

// Reviewed against the v10.5.2 pack in deploy/Dockerfile. The HTTP templates
// use fixed, target-relative GET paths. TLS templates inspect the peer
// certificate on the confirmed HTTPS port. Tags alone cannot guarantee this.
var official = []struct {
	path, digest string
	tags         []string
}{
	{"http/technologies/wordpress-detect.yaml", "fd1601451ef46e18a5e0f4d9305b1fb297c2611a7f026776d8be31efb3d78558", []string{"tech"}},
	{"http/technologies/joomla-detect.yaml", "d8a63e0eb8915dd84f9b750469113f696cb1d3cefc23fd362d6fe1ea501bf2c0", []string{"tech"}},
	{"http/technologies/nginx/nginx-version.yaml", "aa410fb8361f2109ac247b16419040cc2cce1e3d9c76f0a51593806e7c1b7cd7", []string{"tech"}},
	{"http/exposed-panels/apache/apache-tomcat-exposed.yaml", "ac90cf4c9277e8697079bd6bf995a0938dc30553112dd823642ebb6d473f2ecf", []string{"panel"}},
	{"http/technologies/bunkerweb-detect.yaml", "2ead6904bf3df85f3328e2f781f7ad61dfa300cf1fc8a7a07d6281fcd7c2c301", []string{"tech", "waf"}},
	{"http/technologies/favicon-detect.yaml", "45ca119578a0f9c5a016c1df8a030c6fc2f79823ad3387744d5dddda74c5b123", []string{"tech", "favicon"}},
	{"ssl/expired-ssl.yaml", "23e2fa79491ae665e809b9af4b6636f7b4c21ad7d05c5d54801ecd0c29a16088", []string{"ssl"}},
	{"ssl/self-signed-ssl.yaml", "bfdadaaa257aba1ba29c095d0d44237a44a2d5ceb4f58cf0993ec1a484af6fc1", []string{"ssl"}},
}

func (s *Scanner) officialTemplates(dir string, tags []string, hasTLS bool) (httpPaths, sslPaths []string, err error) {
	root := s.TemplatesDir
	if root == "" {
		root = DefaultTemplates
	}
	for _, t := range official {
		ssl := strings.HasPrefix(t.path, "ssl/")
		if (ssl && !hasTLS) || !slices.ContainsFunc(t.tags, func(tag string) bool { return slices.Contains(tags, tag) }) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, t.path))
		if err != nil {
			return nil, nil, fmt.Errorf("nuclei: read approved template %s: %w", t.path, err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != t.digest {
			return nil, nil, fmt.Errorf("nuclei: approved template checksum changed: %s", t.path)
		}
		name := "official-" + filepath.Base(t.path)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return nil, nil, fmt.Errorf("nuclei: stage approved template: %w", err)
		}
		if ssl {
			sslPaths = append(sslPaths, name)
		} else {
			httpPaths = append(httpPaths, name)
		}
	}
	return httpPaths, sslPaths, nil
}

func (s *Scanner) customTemplates(ctx context.Context, dir string, paths []string) ([]string, error) {
	var inputs []string
	if s.LoadSignatures != nil {
		var err error
		inputs, err = s.LoadSignatures(ctx)
		if err != nil {
			return nil, err
		}
	}
	if s.CustomDir != "" {
		entries, err := os.ReadDir(s.CustomDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("nuclei: read custom signatures directory: %w", err)
		}
		for _, entry := range entries {
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if entry.Type().IsRegular() && (ext == ".yaml" || ext == ".yml") {
				paths = append(paths, filepath.Join(s.CustomDir, entry.Name()))
			}
		}
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("nuclei: read custom signature: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(f, signatures.MaxTemplateBytes+1))
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("nuclei: read custom signature: %w", err)
		}
		inputs = append(inputs, string(data))
	}
	if len(inputs) == 0 {
		return nil, nil
	}

	const staged = "custom"
	if err := os.Mkdir(filepath.Join(dir, staged), 0700); err != nil {
		return nil, fmt.Errorf("nuclei: stage custom signatures: %w", err)
	}
	seen := make(map[string]string, len(inputs))
	excluded := strings.Split(excludedTags, ",")
	for _, source := range inputs {
		data := []byte(source)
		t, issues := signatures.Validate(data)
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var doc yaml.Node
		if len(issues) != 0 || decoder.Decode(&doc) != nil || decoder.Decode(&doc) != io.EOF {
			// The validator inspects one document. Stage only single-document YAML.
			return nil, errors.New("nuclei: custom signature failed validation")
		}
		if slices.ContainsFunc(t.Tags, func(tag string) bool {
			return slices.Contains(excluded, strings.ToLower(tag))
		}) {
			continue
		}
		if prior, ok := seen[t.ID]; ok {
			if prior != source {
				return nil, fmt.Errorf("nuclei: duplicate custom signature ID %s", t.ID)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, staged, t.ID+".yaml"), data, 0600); err != nil {
			return nil, fmt.Errorf("nuclei: stage custom signature: %w", err)
		}
		seen[t.ID] = source
	}
	if len(seen) == 0 {
		return nil, nil
	}
	return []string{staged}, nil
}
