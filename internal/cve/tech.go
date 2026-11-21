package cve

import (
	"strings"
	"sync"
)

// techSynonyms maps technology / product names as scanners print them
// (httpx -td = Wappalyzer names, nmap -sV product names, nuclei tech
// template names) to a products.txt vendor:product. Keys are normalized by
// normName. Display names from products.txt are added automatically.
var techSynonyms = map[string]string{
	// web servers / proxies
	"apache": "apache:http_server", "apachehttpserver": "apache:http_server", "apachehttpd": "apache:http_server",
	"httpd": "apache:http_server", "apache2": "apache:http_server",
	"nginx": "f5:nginx", "nginxhttpserver": "f5:nginx",
	"iis": "microsoft:internet_information_services", "microsoftiishttpd": "microsoft:internet_information_services",
	"microsoftiis": "microsoft:internet_information_services",
	"tomcat":       "apache:tomcat", "apachetomcatcoyotejsp": "apache:tomcat", "apachecoyote": "apache:tomcat",
	"jetty": "eclipse:jetty", "caddy": "caddyserver:caddy", "caddyhttpd": "caddyserver:caddy",
	"openresty": "openresty:openresty", "squid": "squid-cache:squid", "squidhttpproxy": "squid-cache:squid",
	"haproxy": "haproxy:haproxy", "varnish": "varnish_cache_project:varnish_cache",
	"varnishhttpaccelerator": "varnish_cache_project:varnish_cache", "traefik": "traefik:traefik",
	"envoy": "envoyproxy:envoy", "nodejs": "nodejs:node.js", "node": "nodejs:node.js",
	"werkzeug": "palletsprojects:werkzeug", "werkzeughttpd": "palletsprojects:werkzeug",
	"gunicorn": "gunicorn:gunicorn", "lighttpd": "lighttpd:lighttpd", "apachetrafficserver": "apache:traffic_server",
	// languages / frameworks
	"php": "php:php", "openssl": "openssl:openssl", "express": "openjsf:express",
	"nodejsexpressframework": "openjsf:express", "django": "djangoproject:django",
	"rubyonrails": "rubyonrails:rails", "rails": "rubyonrails:rails", "springboot": "vmware:spring_boot",
	"struts": "apache:struts", "apachestruts": "apache:struts", "jquery": "jquery:jquery",
	// CMS / apps
	"wordpress": "wordpress:wordpress", "joomla": `joomla:joomla\!`, "drupal": "drupal:drupal",
	"phpmyadmin": "phpmyadmin:phpmyadmin", "jenkins": "jenkins:jenkins", "grafana": "grafana:grafana",
	"gitlab": "gitlab:gitlab", "gitea": "gitea:gitea", "kibana": "elastic:kibana",
	"elasticsearch": "elastic:elasticsearch", "elasticsearchrestapi": "elastic:elasticsearch",
	"nextcloud": "nextcloud:nextcloud_server", "roundcube": "roundcube:webmail", "roundcubewebmail": "roundcube:webmail",
	"zabbix": "zabbix:zabbix", "nagios": "nagios:nagios", "nagiosxi": "nagios:nagios",
	"sonarqube": "sonarsource:sonarqube", "mediawiki": "mediawiki:mediawiki", "moodle": "moodle:moodle",
	"confluence": "atlassian:confluence_server", "atlassianconfluence": "atlassian:confluence_server",
	"jira": "atlassian:jira_server", "atlassianjira": "atlassian:jira_server",
	"webmin": "webmin:webmin", "webminhttpd": "webmin:webmin", "miniserv": "webmin:webmin",
	"activemq": "apache:activemq", "solr": "apache:solr", "minio": "minio:minio", "rabbitmq": "vmware:rabbitmq",
	"keycloak": "redhat:keycloak", "prometheus": "prometheus:prometheus", "portainer": "portainer:portainer",
	"outlookwebapp": "microsoft:exchange_server", "microsoftexchange": "microsoft:exchange_server",
	"zimbra": "zimbra:collaboration",
	// remote access
	"openssh": "openbsd:openssh", "dropbear": "dropbear_ssh_project:dropbear_ssh",
	"dropbearsshd": "dropbear_ssh_project:dropbear_ssh", "libssh": "libssh:libssh",
	"tightvnc": "tightvnc:tightvnc", "realvnc": "realvnc:vnc_server", "openvpn": "openvpn:openvpn",
	// ftp / mail / dns / file
	"vsftpd": "beasts:vsftpd", "proftpd": "proftpd:proftpd", "pureftpd": "pureftpd:pure-ftpd",
	"filezillaserver": "filezilla-project:filezilla_server", "filezillaftpd": "filezilla-project:filezilla_server",
	"exim": "exim:exim", "eximsmtpd": "exim:exim", "postfix": "postfix:postfix", "postfixsmtpd": "postfix:postfix",
	"sendmail": "sendmail:sendmail", "dovecot": "dovecot:dovecot", "dovecotimapd": "dovecot:dovecot",
	"dovecotpop3d": "dovecot:dovecot", "bind": "isc:bind", "iscbind": "isc:bind", "dnsmasq": "thekelleys:dnsmasq",
	"samba": "samba:samba", "sambasmbd": "samba:samba", "netsnmp": "net-snmp:net-snmp", "cups": "apple:cups",
	// databases
	"mysql": "oracle:mysql", "mariadb": "mariadb:mariadb", "postgresql": "postgresql:postgresql",
	"postgresqldb": "postgresql:postgresql", "postgres": "postgresql:postgresql", "redis": "redis:redis",
	"rediskeyvaluestore": "redis:redis", "mongodb": "mongodb:mongodb", "memcached": "memcached:memcached",
	"mssql": "microsoft:sql_server", "microsoftsqlserver": "microsoft:sql_server", "couchdb": "apache:couchdb",
	"apachecouchdb": "apache:couchdb", "influxdb": "influxdata:influxdb", "influxdbhttpadmin": "influxdata:influxdb",
	// appliances
	"fortigate": "fortinet:fortios", "fortinetfortigate": "fortinet:fortios", "fortios": "fortinet:fortios",
	"pulsesecure": "ivanti:connect_secure", "ivanticonnectsecure": "ivanti:connect_secure",
	"citrixnetscaler": "citrix:netscaler_application_delivery_controller",
	"netscaler":       "citrix:netscaler_application_delivery_controller", "mikrotik": "mikrotik:routeros",
	"routeros": "mikrotik:routeros", "mikrotikrouteros": "mikrotik:routeros", "sonicwall": "sonicwall:sonicos",
	"panos": "paloaltonetworks:pan-os", "paloalto": "paloaltonetworks:pan-os",
	"synologydsm": "synology:diskstation_manager", "qnap": "qnap:qts", "qnapqts": "qnap:qts",
}

// normName lowercases and keeps only letters and digits.
func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	techOnce  sync.Once
	techIndex map[string]string
)

func techTable() map[string]string {
	techOnce.Do(func() {
		techIndex = make(map[string]string, len(techSynonyms)+128)
		for _, p := range Products() {
			techIndex[normName(p.Name)] = p.NVD[0]
		}
		for k, v := range techSynonyms {
			techIndex[k] = v
		}
	})
	return techIndex
}

// CPEForTech maps a technology or product name to a normalized
// "vendor:product" CPE of products.txt, for parsers whose tool doesn't emit
// CPEs. It accepts httpx -td / Wappalyzer names with an optional
// ":version" or "/version" ("Nginx:1.19.0", "Apache HTTP Server:2.4.49",
// "Apache Tomcat/9.0.50", "WordPress"), nmap product names ("Apache httpd",
// "OpenSSH", "Exim smtpd") and nuclei tech names ("nginx", "apache-detect").
// version is the part after ":" or "/" if any. ok is false for names we
// don't track.
func CPEForTech(name string) (cpe, version string, ok bool) {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, ":"); i > 0 && i+1 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' {
		name, version = name[:i], name[i+1:]
	} else if i := strings.LastIndex(name, "/"); i > 0 && i+1 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' {
		name, version = name[:i], name[i+1:]
	}
	key := strings.TrimSuffix(normName(name), "detect")
	if cpe, ok = techTable()[key]; ok {
		return cpe, version, true
	}
	return "", "", false
}

// FormatCPE formats a normalized "vendor:product" CPE with an optional version.
func FormatCPE(cpe, version string) string {
	cpe = strings.TrimSpace(cpe)
	version = strings.TrimSpace(version)
	if cpe == "" || version == "" {
		return cpe
	}
	return cpe + ":" + version
}
