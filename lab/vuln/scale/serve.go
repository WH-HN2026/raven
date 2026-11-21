package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

//go:embed jenkins-favicon.ico
var jenkinsFavicon []byte

// readyFile is written once every address answers; the compose healthcheck tests it.
const readyFile = "/tmp/ready"

type key struct {
	addr netip.Addr
	port int
}

// serve adds the layout's addresses to dev, binds one listener per
// (address, port), checks that each answers and then serves until killed.
func serve(c Config, dev string) error {
	hosts, _ := Layout(c)
	svcs := map[key]Service{}
	var batch bytes.Buffer
	for _, h := range hosts {
		a := h.Addr()
		if !inScale(a) { // never add an address outside 10.77.64.0/18
			return fmt.Errorf("refusing address %s outside %s", a, scaleRange)
		}
		fmt.Fprintf(&batch, "address replace %s/32 dev %s\n", a, dev)
		for _, s := range Services(c.Seed, h) {
			svcs[key{a, s.Port}] = s
		}
	}
	start := time.Now()
	cmd := exec.Command("ip", "-batch", "-")
	cmd.Stdin = &batch
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip -batch: %w: %s", err, out)
	}
	log.Printf("added %d addresses to %s in %s", len(hosts), dev, time.Since(start).Round(time.Millisecond))

	cert, err := selfSigned()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handle(svcs, w, r) }),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Second,
		ErrorLog:          log.New(discard{}, "", 0),
	}
	for k, s := range svcs {
		ln, err := net.Listen("tcp4", net.JoinHostPort(k.addr.String(), strconv.Itoa(k.port)))
		if err != nil {
			return fmt.Errorf("listen %s:%d: %w", k.addr, k.port, err)
		}
		switch s.Kind {
		case KindHTTP:
			go srv.Serve(ln) //nolint:errcheck // runs until the process ends
		case KindHTTPS:
			go srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})) //nolint:errcheck
		default:
			go acceptRaw(ln, s)
		}
	}
	log.Printf("listening on %d (address, port) pairs", len(svcs))
	if err := selfCheck(hosts, c.Seed); err != nil {
		return err
	}
	if err := os.WriteFile(readyFile, []byte(strconv.Itoa(len(hosts))+"\n"), 0o644); err != nil {
		return err
	}
	log.Printf("ready: %d hosts, %d services, seed %d, epoch %d (%s since start)",
		len(hosts), len(svcs), c.Seed, c.Epoch, time.Since(start).Round(time.Millisecond))
	select {}
}

// selfCheck connects to the first port of every host.
func selfCheck(hosts []Host, seed uint64) error {
	var wg sync.WaitGroup
	errs := make(chan error, len(hosts))
	sem := make(chan struct{}, 256)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			s := Services(seed, h)[0]
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort(h.Addr().String(), strconv.Itoa(s.Port)), 3*time.Second)
			if err != nil {
				errs <- err
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()
	close(errs)
	if err, ok := <-errs; ok {
		return fmt.Errorf("self-check: %w", err)
	}
	return nil
}

func handle(svcs map[key]Service, w http.ResponseWriter, r *http.Request) {
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	ap, err := netip.ParseAddrPort(la.String())
	s, ok := svcs[key{ap.Addr().Unmap(), int(ap.Port())}]
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	for _, h := range s.Headers {
		w.Header().Add(h[0], h[1])
	}
	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		t := html.EscapeString(s.Title)
		fmt.Fprintf(w, "<!doctype html>\n<html><head><title>%s</title></head>\n<body><h1>%s</h1>%s</body></html>\n", t, t, s.Body)
	case r.URL.Path == "/favicon.ico" && s.Extra == ExtraJenkinsFavicon:
		w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
		w.Write(jenkinsFavicon) //nolint:errcheck
	case r.URL.Path == "/manager/html" && s.Extra == ExtraTomcatManager:
		w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<!doctype html><html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1>"+
			"<p>You are not authorized to view this page. Tomcat Manager Application.</p></body></html>\n")
	default:
		http.NotFound(w, r)
	}
}

// acceptRaw serves banner-only ports: ssh, ftp and silent ones.
func acceptRaw(ln net.Listener, s Service) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
			if s.Banner != "" {
				fmt.Fprintf(conn, "%s\r\n", s.Banner)
			}
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				switch s.Kind {
				case KindFTP:
					fmt.Fprint(conn, "530 Please login with USER and PASS.\r\n")
				case KindSSH:
					return // a real server would start the key exchange; the banner is enough
				}
			}
		}()
	}
}

// selfSigned makes the certificate for every HTTPS port, at startup.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject:      pkix.Name{CommonName: "scale.vlab.raven.lab", Organization: []string{"RAVEN vlab"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"scale.vlab.raven.lab"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("self-signed certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
