#!/bin/sh
# Regenerate all test fixtures. Requires: zip (Info-ZIP), 7zz (p7zip/sevenzip).
set -e
cd "$(dirname "$0")/fixtures"

echo "hello world secret content 12345" > plain.txt
printf 'AAAABBBBCCCCDDDD' > small.bin
python3 -c "open('big.txt','w').write('The quick brown fox jumps over the lazy dog. '*500)" 2>/dev/null || \
  perl -e 'print "The quick brown fox jumps over the lazy dog. " x 500' > big.txt

# ZipCrypto (Info-ZIP): stored + deflated + multi-entry + tail-index pw
zip -P abc      zc_3char.zip  plain.txt
zip -P pass123  zc_8char.zip  plain.txt
zip -P Qw7x     zc_mixed.zip  small.bin plain.txt
zip -P 99999999 zc_tail.zip   plain.txt

# ZipCrypto via 7z (deflate + different writer conventions)
7zz a -tzip -mem=ZipCrypto -pk9v2 zc_7z_defl.zip big.txt >/dev/null

# WinZip AES via 7z
7zz a -tzip -mem=AES128 -phunt3r   aes128.zip plain.txt >/dev/null
7zz a -tzip -mem=AES192 -pzz9      aes192.zip small.bin >/dev/null
7zz a -tzip -mem=AES256 -pS3cr3t!9 aes256.zip plain.txt >/dev/null
7zz a -tzip -mem=AES256 -pMeow!42  aes256_defl.zip big.txt >/dev/null

# 7z (delegated engine): LZMA2-compressed payload so hashcat 11600 can verify
7zz a -t7z -m0=lzma2 -pK3y!9 test7z.7z plain.txt small.bin big.txt >/dev/null
7zz a -t7z -pMeow!42 -mhe=on test7z_nohe.7z plain.txt >/dev/null

# RAR5 (delegated engine): needs the `rar` CLI (rarlab freeware)
if command -v rar >/dev/null 2>&1; then
  rar a -pR4r!  test_p.rar plain.txt >/dev/null
  rar a -hpR4r! test_h.rar plain.txt >/dev/null
fi

printf 'wrong1\nwrong2\nQw7x\nhunt3r\nS3cr3t!9\nzz9\n' > mini.dict
printf 'k9v2\nMeow!42\nabc\n' > wl2.dict

echo "fixtures ready:"
ls -1 *.zip
