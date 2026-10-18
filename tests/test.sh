#!/bin/sh
# test.sh - end-to-end test suite for ziprec
# Run from repo root: sh tests/test.sh
set -u
cd "$(dirname "$0")/.."
Z=./ziprec
F=tests/fixtures
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "PASS  $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL  $1"; }

[ -x "$Z" ] || { echo "build first: make"; exit 2; }

echo "== fixtures =="
# regenerate fixtures if missing
if [ ! -f $F/zc_3char.zip ]; then
  mkdir -p $F; echo "hello world secret content 12345" > $F/plain.txt
  printf 'AAAABBBBCCCCDDDD' > $F/small.bin
  zip -P abc $F/zc_3char.zip $F/plain.txt >/dev/null 2>&1 || \
    (cd $F && zip -P abc zc_3char.zip plain.txt)
  (cd $F && zip -P pass123 zc_8char.zip plain.txt && zip -P Qw7x zc_mixed.zip small.bin plain.txt)
fi

echo "== crypto self-test =="
$Z --selftest >/dev/null && ok "selftest" || bad "selftest"

echo "== ZipCrypto brute force =="
R=$($Z $F/zc_3char.zip -b --min 1 --max 4 --charset '?l' -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: abc" ] && ok "zc brute found abc" || bad "zc brute ($R)"

echo "== ZipCrypto builtin dict+rules =="
R=$($Z $F/zc_8char.zip -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: pass123" ] && ok "dict+rules found pass123" || bad "dict+rules ($R)"

echo "== ZipCrypto deflate entry =="
R=$($Z $F/zc_mixed.zip -d $F/mini.dict -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: Qw7x" ] && ok "zc deflate found Qw7x" || bad "zc deflate ($R)"

echo "== AES-256 =="
R=$($Z $F/aes256.zip -d $F/mini.dict -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: S3cr3t!9" ] && ok "aes256" || bad "aes256 ($R)"

echo "== AES-128 =="
R=$($Z $F/aes128.zip -d $F/mini.dict -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: hunt3r" ] && ok "aes128" || bad "aes128 ($R)"

echo "== AES-192 =="
R=$($Z $F/aes192.zip -d $F/mini.dict -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: zz9" ] && ok "aes192" || bad "aes192 ($R)"

echo "== mask with literals =="
R=$($Z $F/zc_3char.zip -m 'ab?' -y -q 2>&1 | grep FOUND)
echo "$R" | grep -q "FOUND" && bad "literal mask should not match 'ab?'" || true
R=$($Z $F/zc_3char.zip -m '?l?l?l' -y -q 2>&1 | grep FOUND)
[ "$R" = "PASSWORD FOUND: abc" ] && ok "mask ?l?l?l" || bad "mask ($R)"

echo "== checkpoint/resume =="
if [ -f $F/zc_tail.zip ]; then
  rm -f $F/zc_tail.zip.zck
  $Z $F/zc_tail.zip -m '?d?d?d?d?d?d?d?d' -y -q --ckpt-interval 1 &
  P=$!; sleep 0.5; kill -INT $P 2>/dev/null; wait $P 2>/dev/null
  [ -f $F/zc_tail.zip.zck ] && ok "checkpoint written" || bad "no checkpoint"
  R=$($Z $F/zc_tail.zip -m '?d?d?d?d?d?d?d?d' -y -q --resume $F/zc_tail.zip.zck 2>&1 | grep FOUND)
  [ "$R" = "PASSWORD FOUND: 99999999" ] && ok "resume found 99999999" || bad "resume ($R)"
fi

echo "== exhaust handling =="
R=$($Z $F/zc_3char.zip -b --min 1 --max 2 --charset '?d' -y -q 2>&1 | grep exhausted)
[ -n "$R" ] && ok "exhaust reported" || bad "exhaust"

echo "== rules engine (via unit) =="
if [ -x tests/unit ]; then
  tests/unit $F/zc_3char.zip abc >/dev/null 2>&1 && ok "unit harness runs" || bad "unit harness"
fi

echo "== delegated engines (7z / RAR5) =="
cat > /tmp/ziprec_ext_wl.txt <<'EOF'
nope
K3y!9
R4r!
nada
EOF
if command -v john >/dev/null 2>&1 && command -v 7zz >/dev/null 2>&1; then
  R=$($Z $F/test7z.7z -d /tmp/ziprec_ext_wl.txt -y -q 2>&1 | grep FOUND)
  [ "$R" = "PASSWORD FOUND: K3y!9" ] && ok "7z dict found K3y!9" || bad "7z ($R)"
else
  echo "skip  7z (john/7zz missing)"
fi
if command -v john >/dev/null 2>&1 && command -v unrar >/dev/null 2>&1; then
  R=$($Z $F/test_p.rar -d /tmp/ziprec_ext_wl.txt -y -q 2>&1 | grep FOUND)
  [ "$R" = "PASSWORD FOUND: R4r!" ] && ok "rar5 -p found R4r!" || bad "rar5 -p ($R)"
  R=$($Z $F/test_h.rar -d /tmp/ziprec_ext_wl.txt -y -q 2>&1 | grep FOUND)
  [ "$R" = "PASSWORD FOUND: R4r!" ] && ok "rar5 -hp found R4r!" || bad "rar5 -hp ($R)"
else
  echo "skip  rar5 (john/unrar missing)"
fi

echo
echo "results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
