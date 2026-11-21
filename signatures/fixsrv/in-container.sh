#!/bin/sh
# Runs inside the raven image with --network none: fixture server on loopback,
# then nuclei per template against its own fixture and the neutral one.
/w/fixsrv /pack/testdata /tmp/ports &
sleep 1
NEUTRAL=$(grep '^_neutral ' /tmp/ports | cut -d' ' -f2)
pass=0; fail=0
while read -r id port; do
  [ "$id" = "_neutral" ] && continue
  hit=$(nuclei -silent -disable-update-check -no-interactsh -rl 20 -t /pack/$id.yaml -u http://127.0.0.1:$port -jsonl </dev/null 2>/dev/null | grep -c "\"template-id\":\"$id\"")
  neu=$(nuclei -silent -disable-update-check -no-interactsh -rl 20 -t /pack/$id.yaml -u http://127.0.0.1:$NEUTRAL -jsonl </dev/null 2>/dev/null | grep -c "\"template-id\":\"$id\"")
  if [ "$hit" -ge 1 ] && [ "$neu" -eq 0 ]; then
    echo "PASS $id (fixture hits=$hit, neutral hits=0)"; pass=$((pass+1))
  else
    echo "FAIL $id (fixture hits=$hit, neutral hits=$neu)"; fail=$((fail+1))
  fi
done < /tmp/ports
echo "nuclei proof: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
