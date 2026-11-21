package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type page struct {
	title   string
	headers map[string]string
}

var pages = map[string]page{
	"staging":        {"RAVEN Staging", map[string]string{"X-Environment": "staging"}},
	"printer":        {"RAVEN Lab Printer Status", map[string]string{"Server": "LabPrinter/1.0", "X-Device-Type": "printer"}},
	"tls-selfsigned": {"RAVEN Self-signed TLS", nil},
	"tls-expired":    {"RAVEN Expired TLS", nil},
	"apache":         {"RAVEN Apache Banner Fixture", map[string]string{"Server": "Apache/2.4.49"}},
	"flap":           {"RAVEN Flapping Host", map[string]string{"X-Lab-Host": "flap"}},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "generate-certs" {
		return generateCerts(args[1])
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: fixtures <fixture> or fixtures generate-certs <directory>")
	}
	name := args[0]
	if name == "ssh" {
		return serveSSHBanner()
	}
	p, ok := pages[name]
	if !ok {
		return fmt.Errorf("unknown fixture %q", name)
	}
	server := http.Server{
		Addr:              ":80",
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			for name, value := range p.headers {
				w.Header().Set(name, value)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><title>%s</title><h1>%s</h1>\n", p.title, p.title)
		}),
	}
	if name == "tls-selfsigned" || name == "tls-expired" {
		server.Addr = ":443"
		return server.ListenAndServeTLS("/certs/"+name+".crt", "/certs/"+name+".key")
	}
	return server.ListenAndServe()
}

func serveSSHBanner() error {
	listener, err := net.Listen("tcp", ":22")
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		io.WriteString(conn, "SSH-2.0-OpenSSH_7.4\r\n")
		conn.Close()
	}
}
