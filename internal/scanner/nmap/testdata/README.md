# nmap fixtures

`lab.xml` is real output of nmap 7.99 (from the `raven` image), run with the
exact command `BuildArgs` produces (see `TestBuildArgsExact`), against
throwaway containers on an isolated `--internal` docker network. Nothing
else was scanned.

| IP | What runs there |
|---|---|
| 172.31.250.10 | nginx on 80 and 443 (self-signed TLS, title "RAVEN S2 Test Page") |
| 172.31.250.11 | OpenSSH |
| 172.31.250.12 | OpenSSH + nginx on 80 and 443 |
| 172.31.250.20 | nothing (down host) |

Ports scanned: `22,80,443,8080` (8080 closed everywhere), `--max-rate 100`.

To regenerate (target image: alpine + nginx + openssl + openssh-server with a
self-signed cert and an index page titled "RAVEN S2 Test Page"):

```sh
docker network create --internal --subnet 172.31.250.0/24 raven-s2-test
docker run -d --rm --name s2-web   --network raven-s2-test --ip 172.31.250.10 raven-s2-target nginx -g "daemon off;"
docker run -d --rm --name s2-ssh   --network raven-s2-test --ip 172.31.250.11 raven-s2-target /usr/sbin/sshd -D -e
docker run -d --rm --name s2-mixed --network raven-s2-test --ip 172.31.250.12 raven-s2-target sh -c "/usr/sbin/sshd && nginx -g 'daemon off;'"
docker run --rm --network raven-s2-test --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint nmap raven:local \
  -sS -sV -PE -PP -PS21,22,23,25,80,443,445,3389,8080 -PA80,443 -p 22,80,443,8080 \
  --script http-title,http-headers,ssl-cert,banner --max-rate 100 -T3 --max-retries 2 \
  --host-timeout 15m --script-timeout 30s -n -v --reason -oX - \
  172.31.250.10 172.31.250.11 172.31.250.12 172.31.250.20 > lab.xml
```

The integration test (`-tags integration`) runs `Run` itself. nmap isn't on
dev hosts, so build a static test binary and run it in the `raven` image on the
same network:

```sh
CGO_ENABLED=0 go test -c -tags integration -o /tmp/nmap.test ./internal/scanner/nmap/
docker run --rm --network raven-s2-test --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /tmp/nmap.test:/nmap.test:ro -w /tmp \
  -e RAVEN_NMAP_IT_TARGETS=172.31.250.10,172.31.250.11,172.31.250.12,172.31.250.20 \
  --entrypoint /nmap.test raven:local -test.v -test.run TestRun
docker rm -f s2-web s2-ssh s2-mixed; docker network rm raven-s2-test
```
