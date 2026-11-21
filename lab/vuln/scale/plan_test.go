package main

import (
	"net/netip"
	"slices"
	"testing"
)

func TestInScale(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"10.77.64.0", false}, // network
		{"10.77.64.1", true},
		{"10.77.100.200", true},
		{"10.77.127.254", true},
		{"10.77.127.255", false}, // broadcast
		{"10.77.63.255", false},
		{"10.77.128.0", false},
		{"10.77.0.1", false},    // gateway = host
		{"10.77.254.10", false}, // RAVEN
		{"172.30.0.20", false},  // L1
		{"::ffff:10.77.64.5", false},
	} {
		if got := inScale(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("inScale(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestLayoutPlacement(t *testing.T) {
	for _, n := range []int{1, 256, 1024, 4096} {
		hosts, ch := Layout(Config{Hosts: n, Seed: 1})
		if len(hosts) != n {
			t.Fatalf("n=%d: got %d hosts", n, len(hosts))
		}
		if len(ch.New)+len(ch.Gone)+len(ch.Changed) != 0 {
			t.Errorf("n=%d: epoch 0 has churn %+v", n, ch)
		}
		seen := map[netip.Addr]bool{}
		for _, h := range hosts {
			a := h.Addr()
			if !inScale(a) {
				t.Fatalf("n=%d: %s outside the scale range", n, a)
			}
			if seen[a] {
				t.Fatalf("n=%d: duplicate %s", n, a)
			}
			seen[a] = true
		}
	}
	// spread: 256 hosts are not packed into the first /24s
	hosts, _ := Layout(Config{Hosts: 256, Seed: 1})
	third := map[byte]bool{}
	for _, h := range hosts {
		third[h.Addr().As4()[2]] = true
	}
	if len(third) < 64 {
		t.Errorf("256 hosts fall into only %d /24s", len(third))
	}
}

func TestLayoutDeterministicAndSeeded(t *testing.T) {
	a, _ := Layout(Config{Hosts: 512, Seed: 1, Epoch: 3})
	b, _ := Layout(Config{Hosts: 512, Seed: 1, Epoch: 3})
	if !slices.Equal(a, b) {
		t.Fatal("same config, different layouts")
	}
	c, _ := Layout(Config{Hosts: 512, Seed: 2, Epoch: 3})
	if slices.Equal(a, c) {
		t.Fatal("seed does not change the layout")
	}
}

func TestChurn(t *testing.T) {
	for _, n := range []int{256, 1024, 4096} {
		for epoch := 1; epoch <= 3; epoch++ {
			prev, _ := Layout(Config{Hosts: n, Seed: 1, Epoch: epoch - 1})
			cur, ch := Layout(Config{Hosts: n, Seed: 1, Epoch: epoch})
			if len(cur) != n {
				t.Fatalf("n=%d e=%d: %d hosts", n, epoch, len(cur))
			}
			pv := map[uint32]int{}
			for _, h := range prev {
				pv[h.Off] = h.Variant
			}
			cv := map[uint32]int{}
			for _, h := range cur {
				cv[h.Off] = h.Variant
			}
			var gone, added, changed []uint32
			for off := range pv {
				if _, ok := cv[off]; !ok {
					gone = append(gone, off)
				}
			}
			for off, v := range cv {
				pvv, ok := pv[off]
				switch {
				case !ok:
					added = append(added, off)
				case v != pvv:
					changed = append(changed, off)
				}
			}
			slices.Sort(gone)
			slices.Sort(added)
			slices.Sort(changed)
			if !slices.Equal(gone, ch.Gone) || !slices.Equal(added, ch.New) || !slices.Equal(changed, ch.Changed) {
				t.Fatalf("n=%d e=%d: reported churn does not match the layouts", n, epoch)
			}
			if want := rate(n, goneRate); len(gone) != want || len(added) != want {
				t.Errorf("n=%d e=%d: gone %d new %d, want %d", n, epoch, len(gone), len(added), want)
			}
			if want := rate(n, edgeRate); len(changed) != want {
				t.Errorf("n=%d e=%d: changed %d, want %d", n, epoch, len(changed), want)
			}
		}
	}
}

func TestChangedHostsChangeFingerprints(t *testing.T) {
	_, ch := Layout(Config{Hosts: 1024, Seed: 1, Epoch: 1})
	for _, off := range ch.Changed {
		a := Services(1, Host{Off: off, Variant: 0})
		b := Services(1, Host{Off: off, Variant: 1})
		if len(a) != len(b) {
			t.Fatalf("%s: churn changed the port count", addrAt(off))
		}
		for i := range a {
			if a[i].Port != b[i].Port {
				t.Fatalf("%s: churn changed the ports", addrAt(off))
			}
		}
		if diffServices(a, b) == 0 {
			t.Errorf("%s (%s): variant bump changes nothing visible", addrAt(off), personaNames[personaOf(1, off)])
		}
	}
}

func TestEveryPersonaChangesOnBump(t *testing.T) {
	seen := map[string]bool{}
	for off := uint32(1); off < 4000 && len(seen) < len(personaNames); off++ {
		name := personaNames[personaOf(1, off)]
		for v := range 4 {
			if diffServices(Services(1, Host{Off: off, Variant: v}), Services(1, Host{Off: off, Variant: v + 1})) == 0 {
				t.Fatalf("persona %s at %s: variant %d→%d changes nothing", name, addrAt(off), v, v+1)
			}
		}
		seen[name] = true
	}
	if len(seen) != len(personaNames) {
		t.Fatalf("only %d personas placed", len(seen))
	}
}

func TestServicesUseProfilePorts(t *testing.T) {
	allowed := []int{21, 22, 80, 443, 8080, 8443, 9100}
	hosts, _ := Layout(Config{Hosts: 4096, Seed: 1})
	for _, h := range hosts {
		s := Services(1, h)
		if len(s) == 0 {
			t.Fatalf("%s has no services", h.Addr())
		}
		for i, sv := range s {
			if !slices.Contains(allowed, sv.Port) {
				t.Fatalf("%s: port %d not in the vuln-lab-scale profile", h.Addr(), sv.Port)
			}
			if i > 0 && s[i-1].Port >= sv.Port {
				t.Fatalf("%s: ports not sorted/unique", h.Addr())
			}
		}
	}
}

func TestExpect(t *testing.T) {
	x0 := Expect(Config{Hosts: 256, Seed: 1})
	if x0.Hosts != 256 || x0.Services < 256 || x0.HostsNew != 0 {
		t.Fatalf("epoch 0: %+v", x0)
	}
	x := Expect(Config{Hosts: 256, Seed: 1, Epoch: 1})
	if x.HostsNew != 8 || x.HostsGone != 8 || x.ServicesNew != 0 || x.ServicesGone != 0 {
		t.Fatalf("epoch 1 host churn: %+v", x)
	}
	if x.HostsChanged != 13 || x.ServicesChanged < 13 {
		t.Fatalf("epoch 1 changed: %+v", x)
	}
	if x.PortsOnNewHosts < 8 || x.PortsOnGoneHosts < 8 {
		t.Fatalf("epoch 1 ports: %+v", x)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{{Hosts: 0}, {Hosts: 4097}, {Hosts: 10, Epoch: -1}} {
		if c.validate() == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if err := (Config{Hosts: 4096, Epoch: 5}).validate(); err != nil {
		t.Error(err)
	}
}
