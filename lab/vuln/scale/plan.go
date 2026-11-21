package main

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
)

// The scale layer lives in 10.77.64.0/18 (docs/vuln-lab.md §2.2, §5).
var scaleRange = netip.MustParsePrefix("10.77.64.0/18")

const (
	rangeSize = 1 << 14 // addresses in the /18
	maxHosts  = 4096
	goneRate  = 0.03 // per epoch: hosts that disappear
	newRate   = 0.03 // per epoch: hosts that appear
	edgeRate  = 0.05 // per epoch: hosts whose version or title changes
)

// Config selects one deterministic layout of the scale layer.
type Config struct {
	Hosts int    // occupied addresses, 1..4096
	Seed  uint64 // placement and persona seed
	Epoch int    // churn generation, ≥ 0
}

func (c Config) validate() error {
	if c.Hosts < 1 || c.Hosts > maxHosts {
		return fmt.Errorf("hosts must be 1..%d, got %d", maxHosts, c.Hosts)
	}
	if c.Epoch < 0 {
		return fmt.Errorf("epoch must be ≥ 0, got %d", c.Epoch)
	}
	return nil
}

// Host is one occupied address with its persona variant.
type Host struct {
	Off     uint32 // offset inside the /18 (1..16382)
	Variant int    // bumped by churn "changed"
}

func (h Host) Addr() netip.Addr { return addrAt(h.Off) }

func addrAt(off uint32) netip.Addr {
	b := scaleRange.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += off
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// inScale reports whether a is a usable host address of the scale range
// (not the network or broadcast address). The swarm refuses anything else.
func inScale(a netip.Addr) bool {
	if !a.Is4() || !scaleRange.Contains(a) {
		return false
	}
	first := scaleRange.Addr()
	last := addrAt(rangeSize - 1)
	return a != first && a != last
}

// mix is splitmix64 over (seed, salt, off): a stable pseudo-random score.
func mix(seed, salt uint64, off uint32) uint64 {
	z := seed*0x9e3779b97f4a7c15 ^ salt*0xbf58476d1ce4e5b9 ^ uint64(off)*0x94d049bb133111eb
	z += 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// pick returns the k offsets of from with the lowest score for salt.
func pick(seed, salt uint64, from []uint32, k int) []uint32 {
	s := slices.Clone(from)
	slices.SortFunc(s, func(a, b uint32) int {
		return cmp.Or(cmp.Compare(mix(seed, salt, a), mix(seed, salt, b)), cmp.Compare(a, b))
	})
	return s[:min(k, len(s))]
}

func rate(n int, r float64) int { return max(1, int(math.Round(float64(n)*r))) }

// Churn of one epoch versus the previous one.
type Churn struct {
	Gone, New, Changed []uint32
}

// Layout computes the occupied hosts of c.Epoch and the churn that led to it
// (empty for epoch 0). It is deterministic in (Hosts, Seed, Epoch).
func Layout(c Config) ([]Host, Churn) {
	all := make([]uint32, 0, rangeSize-2)
	for off := uint32(1); off < rangeSize-1; off++ {
		all = append(all, off)
	}
	present := map[uint32]int{} // offset → variant
	for _, off := range pick(c.Seed, 0, all, c.Hosts) {
		present[off] = 0
	}
	var ch Churn
	for e := 1; e <= c.Epoch; e++ {
		salt := uint64(e) * 16
		cur := sortedKeys(present)
		ch.Gone = pick(c.Seed, salt+1, cur, rate(c.Hosts, goneRate))
		var absent []uint32
		for _, off := range all {
			if _, ok := present[off]; !ok {
				absent = append(absent, off)
			}
		}
		ch.New = pick(c.Seed, salt+2, absent, rate(c.Hosts, newRate))
		for _, off := range ch.Gone {
			delete(present, off)
		}
		stay := sortedKeys(present)
		ch.Changed = pick(c.Seed, salt+3, stay, rate(c.Hosts, edgeRate))
		for _, off := range ch.Changed {
			present[off]++
		}
		for _, off := range ch.New {
			present[off] = 0
		}
	}
	hosts := make([]Host, 0, len(present))
	for _, off := range sortedKeys(present) {
		hosts = append(hosts, Host{Off: off, Variant: present[off]})
	}
	for _, s := range [][]uint32{ch.Gone, ch.New, ch.Changed} {
		slices.Sort(s)
	}
	return hosts, ch
}

func sortedKeys(m map[uint32]int) []uint32 {
	k := make([]uint32, 0, len(m))
	for off := range m {
		k = append(k, off)
	}
	slices.Sort(k)
	return k
}

// Expectation is what RAVEN's Changes (GET /api/changes summary) should
// report between the runs of epoch-1 and epoch, plus the totals of epoch.
type Expectation struct {
	Epoch           int `json:"epoch"`
	Hosts           int `json:"hosts"`
	Services        int `json:"services"`
	HTTPServices    int `json:"http_services"`
	HostsNew        int `json:"hosts_new"`
	HostsGone       int `json:"hosts_gone"`
	ServicesNew     int `json:"services_new"`
	ServicesGone    int `json:"services_gone"`
	ServicesChanged int `json:"services_changed"`
	HostsChanged    int `json:"hosts_changed"`
	// Ports listed on new / gone hosts (not counted as services_new/gone by RAVEN).
	PortsOnNewHosts  int `json:"ports_on_new_hosts"`
	PortsOnGoneHosts int `json:"ports_on_gone_hosts"`
}

// Expect computes the expectation for c (epoch 0: totals only).
func Expect(c Config) Expectation {
	hosts, ch := Layout(c)
	x := Expectation{Epoch: c.Epoch, Hosts: len(hosts)}
	for _, h := range hosts {
		for _, s := range Services(c.Seed, h) {
			x.Services++
			if s.Kind == KindHTTP || s.Kind == KindHTTPS {
				x.HTTPServices++
			}
		}
	}
	if c.Epoch == 0 {
		return x
	}
	x.HostsNew, x.HostsGone = len(ch.New), len(ch.Gone)
	for _, off := range ch.New {
		x.PortsOnNewHosts += len(Services(c.Seed, Host{Off: off}))
	}
	prev, _ := Layout(Config{Hosts: c.Hosts, Seed: c.Seed, Epoch: c.Epoch - 1})
	variant := map[uint32]int{}
	for _, h := range prev {
		variant[h.Off] = h.Variant
	}
	for _, off := range ch.Gone {
		x.PortsOnGoneHosts += len(Services(c.Seed, Host{Off: off, Variant: variant[off]}))
	}
	for _, off := range ch.Changed {
		before := Services(c.Seed, Host{Off: off, Variant: variant[off]})
		after := Services(c.Seed, Host{Off: off, Variant: variant[off] + 1})
		n := diffServices(before, after)
		x.ServicesChanged += n
		if n > 0 {
			x.HostsChanged++
		}
	}
	return x
}

// diffServices counts ports whose visible fingerprint differs. Churn never
// adds or removes ports on a host that stays, so the port sets are equal.
func diffServices(a, b []Service) int {
	n := 0
	for i := range a {
		if a[i].Fingerprint() != b[i].Fingerprint() {
			n++
		}
	}
	return n
}

func (x Expectation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "epoch %d: %d hosts, %d services (%d HTTP/HTTPS)\n", x.Epoch, x.Hosts, x.Services, x.HTTPServices)
	if x.Epoch > 0 {
		fmt.Fprintf(&b, "vs epoch %d: hosts_new %d, hosts_gone %d, services_new %d, services_gone %d, services_changed %d (on %d hosts)\n",
			x.Epoch-1, x.HostsNew, x.HostsGone, x.ServicesNew, x.ServicesGone, x.ServicesChanged, x.HostsChanged)
		fmt.Fprintf(&b, "ports listed on new hosts %d, on gone hosts %d\n", x.PortsOnNewHosts, x.PortsOnGoneHosts)
	}
	return b.String()
}
