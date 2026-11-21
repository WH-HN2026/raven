// Command scale is the vuln lab scale layer (docs/vuln-lab.md §5): one
// container that occupies VLAB_SCALE_HOSTS pseudo-random addresses of
// 10.77.64.0/18 and answers on each with a persona (nginx intranet, Apache
// 2.4.49, IIS, Tomcat, Jenkins, staging, printer, camera, router, TLS, SSH,
// FTP). VLAB_SCALE_EPOCH moves the layout by one churn step per epoch.
//
//	scale serve              add the addresses and serve (needs NET_ADMIN)
//	scale expect             expected Changes of this epoch vs the previous one (JSON)
//	scale list               the layout: ip persona port/kind fingerprint
//
// Settings come from VLAB_SCALE_HOSTS (256), VLAB_SCALE_SEED (1),
// VLAB_SCALE_EPOCH (0) and VLAB_SCALE_DEV (eth0).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func envInt(name string, def int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

func configFromEnv() (Config, error) {
	hosts, err := envInt("VLAB_SCALE_HOSTS", 256)
	if err != nil {
		return Config{}, err
	}
	seed, err := envInt("VLAB_SCALE_SEED", 1)
	if err != nil {
		return Config{}, err
	}
	epoch, err := envInt("VLAB_SCALE_EPOCH", 0)
	if err != nil {
		return Config{}, err
	}
	if seed < 0 {
		return Config{}, fmt.Errorf("VLAB_SCALE_SEED must be ≥ 0")
	}
	c := Config{Hosts: hosts, Seed: uint64(seed), Epoch: epoch}
	return c, c.validate()
}

func run(args []string) error {
	c, err := configFromEnv()
	if err != nil {
		return err
	}
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "serve":
		dev := os.Getenv("VLAB_SCALE_DEV")
		if dev == "" {
			dev = "eth0"
		}
		return serve(c, dev)
	case "expect":
		x := Expect(c)
		fmt.Fprint(os.Stderr, x.String())
		return json.NewEncoder(os.Stdout).Encode(x)
	case "list":
		hosts, _ := Layout(c)
		for _, h := range hosts {
			for _, s := range Services(c.Seed, h) {
				fmt.Printf("%s\t%s\t%d/%s\t%s\n", h.Addr(), personaNames[personaOf(c.Seed, h.Off)], s.Port, s.Kind, s.Fingerprint())
			}
		}
		return nil
	default:
		return fmt.Errorf("usage: scale [serve|expect|list]")
	}
}
