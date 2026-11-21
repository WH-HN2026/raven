package cve

import (
	"regexp"
	"strconv"
	"strings"
)

// A version is compared as a list of segments: runs of digits (compared as
// numbers) and runs of letters (compared as strings). Separators (. _ -) only
// split segments. Rules beyond that:
//   - a package revision is not part of the upstream version: "2.4.49-r0",
//     "1.18.0-6ubuntu14", "7.4p1-10+deb9u7" compare as "2.4.49", "1.18.0", "7.4p1";
//   - pre-release words (alpha, beta, rc, pre, dev, …) sort before the
//     release: "2.0rc1" < "2.0"; other letters are post-release: "8.9p1" > "8.9";
//   - trailing zeros don't count: "1.2" == "1.2.0".

var preRelease = map[string]bool{"alpha": true, "beta": true, "rc": true, "pre": true, "dev": true,
	"preview": true, "snapshot": true, "m": true}

// preReleaseSuffix: a "-"/"+"/"~" before one of these keeps the rest ("1.0-rc1").
var preReleaseSuffix = regexp.MustCompile(`^(alpha|beta|rc|pre|dev|preview|snapshot|m)\d*`)

// Upstream strips a leading "v", anything after whitespace or "(", and a
// package revision (from the first "-", "+" or "~" not followed by a
// pre-release word) from a version.
func Upstream(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, " \t("); i >= 0 {
		v = v[:i]
	}
	for i := 1; i < len(v); i++ {
		if strings.IndexByte("-+~", v[i]) >= 0 && !preReleaseSuffix.MatchString(v[i+1:]) {
			return v[:i]
		}
	}
	return v
}

type segment struct {
	num   int64
	alpha string // "" for numeric segments
}

func segments(v string) []segment {
	var out []segment
	for i := 0; i < len(v); {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, _ := strconv.ParseInt(strings.TrimLeft(v[i:j], "0")+"0", 10, 64)
			out = append(out, segment{num: n / 10})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, segment{alpha: v[i:j]})
			i = j
		default:
			i++
		}
	}
	return out
}

// Compare returns -1, 0 or 1 as a is older than, equal to or newer than b.
func Compare(a, b string) int {
	sa, sb := segments(Upstream(a)), segments(Upstream(b))
	for i := 0; i < len(sa) || i < len(sb); i++ {
		switch {
		case i >= len(sa):
			return -tail(sb[i:])
		case i >= len(sb):
			return tail(sa[i:])
		}
		x, y := sa[i], sb[i]
		switch {
		case x.alpha == "" && y.alpha == "":
			if x.num != y.num {
				return cmpInt(x.num, y.num)
			}
		case x.alpha != "" && y.alpha != "":
			if x.alpha != y.alpha {
				return cmpRank(x.alpha, y.alpha)
			}
		case x.alpha != "": // letters vs number: 1.0a < 1.0.1, 1.0rc1 < 1.0.0
			return -1
		default:
			return 1
		}
	}
	return 0
}

// tail is the sign of the extra segments of the longer version.
func tail(rest []segment) int {
	for _, s := range rest {
		switch {
		case s.alpha != "" && preRelease[s.alpha]:
			return -1
		case s.alpha != "" || s.num != 0:
			return 1
		}
	}
	return 0
}

func cmpRank(a, b string) int {
	pa, pb := preRelease[a], preRelease[b]
	switch {
	case pa && !pb:
		return -1
	case pb && !pa:
		return 1
	}
	return strings.Compare(a, b)
}

func cmpInt(a, b int64) int {
	if a < b {
		return -1
	}
	return 1
}

// portable is OpenSSH-style "pN" (portable release N of the same version).
var portable = regexp.MustCompile(`p\d+$`)

// cmpBound compares a detected version with a range bound. A "pN" suffix
// is ignored when the bound has none: NVD's "fixed in 7.5" / "up to 7.4"
// refer to the release, and 7.4p1 is the 7.4 release.
func cmpBound(v, bound string) int {
	v = Upstream(v)
	if !portable.MatchString(Upstream(bound)) {
		v = portable.ReplaceAllString(v, "")
	}
	return Compare(v, bound)
}

// InRange reports whether version v is inside r.
func InRange(v string, r Range) bool {
	if r.Exact != "" {
		return cmpBound(v, r.Exact) == 0 || cmpBound(r.Exact, v) == 0
	}
	if r == (Range{}) {
		return false
	}
	return (r.StartIncl == "" || cmpBound(v, r.StartIncl) >= 0) &&
		(r.StartExcl == "" || cmpBound(v, r.StartExcl) > 0) &&
		(r.EndIncl == "" || cmpBound(v, r.EndIncl) <= 0) &&
		(r.EndExcl == "" || cmpBound(v, r.EndExcl) < 0)
}

// leadingVersion is the first version-looking token of a banner version
// field, e.g. "7.4p1" in "7.4p1 Debian 10+deb9u7".
var leadingVersion = regexp.MustCompile(`(?i)\bv?(\d+(?:[._]\d+)*[a-z0-9._+~-]*)`)

// ExtractVersion returns the version token of a scanner version string, or "".
func ExtractVersion(s string) string {
	m := leadingVersion.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	return m[1]
}

// distroMarker matches the distro build markers banners carry: OpenSSH
// "8.9p1 Ubuntu 3ubuntu0.10", "Debian 10+deb9u7", Apache "(Ubuntu)",
// RPM "el8", Alpine "-r0".
var distroMarker = regexp.MustCompile(`(?i)(ubuntu|debian|\bdeb\d+u\d+|\+deb\d|[.\-_]el\d+|\bel\d+\b|centos|rhel|red ?hat|fedora|\bfc\d+\b|suse|sles|alpine|amzn|raspbian|almalinux|rocky|-r\d+$)`)

// DistroBuild reports whether any of the strings shows a distribution
// build. Distros backport fixes without changing the upstream version, so
// version matching on such builds is low confidence.
// Nmap unrecognized service fingerprints ("SF-Port...") embed the scanner's
// own platform (%P=x86_64-alpine-linux-musl) and are ignored.
func DistroBuild(fields ...string) bool {
	for _, f := range fields {
		if f == "" || strings.HasPrefix(f, "SF-Port") {
			continue
		}
		if distroMarker.MatchString(f) {
			return true
		}
	}
	return false
}
