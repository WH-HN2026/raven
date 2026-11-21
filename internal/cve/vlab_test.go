package cve

import "testing"

// TestEmbeddedDataVulnLab logs what the versions in the organizers' lab
// (lab/organizers/, docs/lab.md) match in the committed dataset, and checks
// the CPEs our scanners emit for them (nmap's vsftpd:vsftpd alias, signature
// metadata) are tracked.
func TestEmbeddedDataVulnLab(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []Instance{
		{CPE: "vsftpd:vsftpd:3.0.2", Product: "vsftpd", Version: "3.0.2"},
		{CPE: "traefik:traefik:3.1.7", Version: "3.1.7"},
		{CPE: "gitea:gitea:28.4.0", Version: "28.4.0"},
		{CPE: "adminer:adminer:6.3.0", Version: "6.3.0"},
		{CPE: "adminer:adminer:4.7.8", Version: "4.7.8"},
		{CPE: "phpmyadmin:phpmyadmin:5.2.3", Version: "5.2.3"},
		{CPE: "vmware:rabbitmq:3.13.7", Version: "3.13.7"},
	} {
		got := m.Match(in)
		n := 0
		var ids []string
		if got != nil {
			n = len(got.Hits)
			for _, h := range got.Hits {
				ids = append(ids, h.ID)
			}
		}
		t.Logf("%s: %d CVEs %v", in.CPE, n, ids)
	}
	for _, c := range []string{"vsftpd:vsftpd", "beasts:vsftpd", "vsftpd_project:vsftpd", "traefik:traefik", "gitea:gitea", "adminer:adminer", "phpmyadmin:phpmyadmin", "vmware:rabbitmq"} {
		if _, ok := m.byCPE[c]; !ok {
			t.Errorf("%s is not a tracked CPE", c)
		}
	}
	if len(m.db.Products["adminer:adminer"]) == 0 {
		t.Error("the dataset has no Adminer CVEs; run make cve-db")
	}
}
