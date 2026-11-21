# Lab records

These are unmodified Nuclei 3.11.1 JSONL records captured on the internal `raven_lab` network with the v10.5.2 official template pack. Captures used `-jsonl -omit-raw -omit-template -no-interactsh -duc -auth=false -no-httpx -disable-redirects -rl 20` and the excludes from the command builder.

- `lab-http.jsonl` used the WordPress detection and Tomcat panel templates with `-type http -tags tech,panel`, targeting the lab WordPress and Tomcat endpoints.
- `lab-ssl.jsonl` used `expired-ssl.yaml` with `-type ssl -tags ssl`, targeting the lab's two TLS endpoints.
- `lab-active.jsonl` used the `nuclei_active` aggressive tag allowlist and exclusions against the lab WordPress (`172.30.0.17:80`), Tomcat (`172.30.0.21:8080`), and simulated Apache (`172.30.0.25:80`) endpoints.
