package changes

import (
	"cmp"
	"slices"
	"strings"

	"github.com/WH-HN2026/raven/internal/db"
)

// orderLists sorts the diff before its five lists are capped. Equal keys
// retain the deterministic IP/port order already established by Diff.
func (r *Result) orderLists(order db.ListOrder) {
	if order.Column == "" || order.Column == "change" {
		return // Each list already contains only one kind of change.
	}
	direction := 1
	if order.Direction == "desc" {
		direction = -1
	}
	for _, group := range [][]ServiceChange{r.ServicesNew, r.ServicesChanged, r.ServicesGone} {
		slices.SortStableFunc(group, func(a, b ServiceChange) int {
			return direction * compareServiceChange(order.Column, a, b)
		})
	}
	for _, group := range []struct {
		hosts []HostChange
		isNew bool
	}{{r.HostsNew, true}, {r.HostsGone, false}} {
		slices.SortStableFunc(group.hosts, func(a, b HostChange) int {
			switch order.Column {
			case "ip":
				return direction * a.IP.Compare(b.IP)
			case "before", "after":
				if group.isNew == (order.Column == "after") {
					return direction * slices.Compare(a.Ports, b.Ports)
				}
				return direction * cmp.Compare(a.OtherRun, b.OtherRun)
			default:
				return 0 // Host rows have the same service and field labels.
			}
		})
	}
}

func compareServiceChange(column string, a, b ServiceChange) int {
	switch column {
	case "ip":
		return a.IP.Compare(b.IP)
	case "service":
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Proto, b.Proto))
	case "field":
		return slices.Compare(a.Fields, b.Fields)
	case "before":
		return cmp.Compare(fingerprintKey(a.Before), fingerprintKey(b.Before))
	case "after":
		return cmp.Compare(fingerprintKey(a.After), fingerprintKey(b.After))
	default:
		return 0
	}
}

func fingerprintKey(f *Fingerprint) string {
	if f == nil {
		return ""
	}
	return strings.ToLower(strings.Join([]string{f.Name, f.Product, f.Version, f.Title, strings.Join(f.Technologies, ", ")}, "\x00"))
}
