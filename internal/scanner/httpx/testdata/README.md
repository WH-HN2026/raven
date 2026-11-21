# httpx v1.12.0 fixture

`nginx.jsonl` is unedited stdout from the release binary. It probed two
throwaway `nginx:stable-alpine` containers on an internal Docker bridge.
The first served a page with an inline icon on port 80 and a same-host
redirect on port 443. The HTTPS destination served two synthetic cookies
and a staging header under a self-signed certificate. The second served
the default nginx welcome page.

The input and command used inside the isolated network:

```sh
printf '%s\n' https://raven-s7-nginx:443 http://172.21.0.2:80 http://172.21.0.3:80 |
    httpx -silent -json -title -sc -irh -tls-grab -favicon -td -fhr -include-chain \
        -nfs -duc -rl 5 -allow 172.21.0.2,172.21.0.3 -auth=false -cdn=false -r 127.0.0.11:53
```

`toxic-latency.jsonl` (V7) is unedited stdout of the same httpx v1.12.0 (from
the `raven` image), run in a one-shot container on the V1 vuln lab network
`raven_vlab` (removed in LB1; the same images now run verbatim from
`lab/organizers/`, see `docs/lab.md`) while the Toxiproxy of the organizers'
`modern-proxy` stack had a `latency` toxic of 3000 ms on the
`wordpress` proxy: Traefik (10.77.2.10:80) and the Toxiproxy listener
(10.77.2.11:8666) both answered in ~3043 ms (`"time":"3.043…s"`).

```sh
printf 'http://10.77.2.10:80\nhttp://10.77.2.11:8666\n' |
    httpx -silent -json -title -sc -irh -tls-grab -favicon -td -fhr -include-chain \
        -nfs -disable-update-check -auth=false -cdn=false -rl 5 -timeout 10 \
        -allow 10.77.2.10,10.77.2.11 -r 127.0.0.11:53
```
