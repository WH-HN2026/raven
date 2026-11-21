// Command fixsrv serves each signatures/testdata/<id> fixture on its own
// loopback port and writes "<id> <port>" lines to a file. _neutral answers
// on every path, the others only on their path.txt (default /). Used by
// prove.sh to run real nuclei against the fixtures inside a container with
// no network.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: fixsrv <testdata dir> <ports file>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	select {}
}

func run(dir, portsFile string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var ports strings.Builder
	for _, e := range entries {
		h, err := fixture(filepath.Join(dir, e.Name()), e.Name() == "_neutral")
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		fmt.Fprintf(&ports, "%s %d\n", e.Name(), ln.Addr().(*net.TCPAddr).Port)
		go func() { _ = http.Serve(ln, h) }()
	}
	return os.WriteFile(portsFile, []byte(ports.String()), 0o644)
}

func fixture(dir string, anyPath bool) (http.Handler, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "response.http"))
	if err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	if b, err := os.ReadFile(filepath.Join(dir, "body.bin")); err == nil {
		body = b
	}
	path := "/"
	if p, err := os.ReadFile(filepath.Join(dir, "path.txt")); err == nil {
		path = strings.TrimSpace(string(p))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !anyPath && r.URL.RequestURI() != path {
			http.NotFound(w, r)
			return
		}
		for k, vs := range resp.Header {
			if k != "Content-Length" {
				w.Header()[k] = vs
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}), nil
}
