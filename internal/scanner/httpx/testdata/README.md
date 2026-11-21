# httpx v1.12.0 fixture

`nginx.jsonl` is unedited stdout from the release binary. It probed two
throwaway `nginx:stable-alpine` containers on an internal Docker bridge.
The first served a page with an inline icon on port 80 and a same-host
redirect on port 443. The HTTPS destination served two synthetic cookies
and a staging header under a self-signed certificate. The second served
the default nginx welcome page.

The input and command used inside the isolated network:

```sh
printf '%s\n' https://asi-s7-nginx:443 http://172.21.0.2:80 http://172.21.0.3:80 |
    httpx -silent -json -title -sc -irh -tls-grab -favicon -td -fhr -include-chain \
        -nfs -duc -rl 5 -allow 172.21.0.2,172.21.0.3 -auth=false -cdn=false -r 127.0.0.11:53
```
