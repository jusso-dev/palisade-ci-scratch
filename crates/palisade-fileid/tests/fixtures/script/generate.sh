#!/bin/sh
# Regenerates the signed script fixtures in this directory (#52).
#
# Every script here is written from scratch by this file and signed by
# jsign, an independent open-source Authenticode signer whose script
# digests agree with OS tooling, with throwaway keys made here, by a
# test-only CA that nothing trusts. No private key is kept.
#
# The matrix is every format the tests read, in every encoding its subject
# interface package signs, with three line-ending conventions:
#
#   <format>-<encoding>-<eol>.<ext>
#     format:   ps1 (PowerShell), ps1xml (PowerShell XML), vbs (VBScript),
#               js (JScript), wsf (Windows Script File)
#     encoding: utf8 (no byte order mark, ASCII text), utf8bom, utf16le,
#               utf16be (not for PowerShell, whose package does not sign it)
#     eol:      crlf, lf, cr (the script's own lines; signers always end
#               the signature block's lines in CRLF)
#
# Text with a byte order mark has non-ASCII characters, one of them outside
# the Basic Multilingual Plane, so the UTF-16 conversion and the WSH block
# position (in UTF-16 units) are exercised. Also:
#
#   psm1-utf8bom-crlf.psm1, psd1-utf8bom-crlf.psd1
#                   The other PowerShell extensions.
#   ps1-nobom-nonascii.ps1, vbs-nobom-nonascii.vbs
#                   Signed by jsign, but non-ASCII text without a byte order
#                   mark: its digest depends on the machine's code page, so
#                   the tests require these to be reported undecodable.
#   ca.der          The test root.
#
# The PowerShell XML, managed object format and signed-metadata cases jsign
# cannot make are built by tests/script.rs itself, with a key it generates.
#
# Needs: openssl (3.x or later), a Java runtime, and the jsign 7.x jar:
#   JSIGN_JAR=/path/to/jsign-7.6.jar sh crates/palisade-fileid/tests/fixtures/script/generate.sh
#
# Keys and serials are random, so a rerun changes every signed file; the
# tests depend only on the files' structure and validity.
set -eu

: "${JSIGN_JAR:?set JSIGN_JAR to the jsign jar}"
out=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

cat > ca.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
CNF
cat > leaf.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
ec ca.key
openssl req -new -key ca.key -subj "/CN=Palisade Test Script Root/O=Palisade Tests" -out ca.csr
openssl x509 -req -in ca.csr -signkey ca.key -days 3650 -extfile ca.cnf -out ca.crt 2>/dev/null
ec leaf.key
openssl req -new -key leaf.key -subj "/CN=Palisade Test Script Signer/O=Palisade Tests" -out leaf.csr
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
  -extfile leaf.cnf -out leaf.crt 2>/dev/null
pass=$(openssl rand -hex 16)
openssl pkcs12 -export -inkey leaf.key -in leaf.crt -certfile ca.crt -passout "pass:$pass" \
  -out leaf.p12
openssl x509 -in ca.crt -outform DER -out "$out/ca.der"

# body FORMAT: the script's lines, LF-separated, UTF-8. `$1` is the format
# and `$2` is "ascii" or "unicode".
body() {
  case "$2" in
    ascii) word='palisade fixture' ;;
    unicode) word='palisade fixture caf\303\251 \342\202\254 \360\237\230\200' ;;
  esac
  case "$1" in
    ps1|psm1|psd1) printf '# %b\nWrite-Output "%b"\n' "$word" "$word" ;;
    ps1xml) printf '<?xml version="1.0"?>\n<Types>\n<!-- %b -->\n</Types>\n' "$word" ;;
    vbs) printf "' %b\nWScript.Echo \"%b\"\n" "$word" "$word" ;;
    js) printf '// %b\nWScript.Echo("%b");\n' "$word" "$word" ;;
    wsf) printf '<job id="t">\n<script language="VBScript">\n'"' "'%b\nWScript.Echo "%b"\n</script>\n</job>\n' \
      "$word" "$word" ;;
  esac
}

# make NAME FORMAT ENCODING EOL: writes NAME in the encoding with the line
# endings, then signs it in place.
make() {
  name=$1 format=$2 encoding=$3 eol=$4
  case "$encoding" in utf8) text=ascii ;; *) text=unicode ;; esac
  body "$format" "$text" > lf.txt
  case "$eol" in
    lf) cp lf.txt eol.txt ;;
    crlf) sed 's/$/\r/' lf.txt > eol.txt ;;
    cr) tr '\n' '\r' < lf.txt > eol.txt ;;
  esac
  case "$encoding" in
    utf8) cp eol.txt "$name" ;;
    utf8bom) { printf '\357\273\277'; cat eol.txt; } > "$name" ;;
    utf16le) { printf '\377\376'; iconv -f UTF-8 -t UTF-16LE eol.txt; } > "$name" ;;
    utf16be) { printf '\376\377'; iconv -f UTF-8 -t UTF-16BE eol.txt; } > "$name" ;;
  esac
  java -jar "$JSIGN_JAR" --quiet --storetype PKCS12 --keystore leaf.p12 --storepass "$pass" \
    --alg SHA-256 "$name"
  cp "$name" "$out/$name"
}

for eol in crlf lf cr; do
  for encoding in utf8 utf8bom utf16le; do
    for format in ps1 ps1xml vbs js wsf; do
      make "$format-$encoding-$eol.$format" "$format" "$encoding" "$eol"
    done
  done
  for format in vbs js wsf; do
    make "$format-utf16be-$eol.$format" "$format" utf16be "$eol"
  done
done
make psm1-utf8bom-crlf.psm1 psm1 utf8bom crlf
make psd1-utf8bom-crlf.psd1 psd1 utf8bom crlf

# Non-ASCII without a byte order mark: jsign reads such a .ps1 as UTF-8 and
# such a .vbs as Windows-1252 (a byte the code page leaves undefined would
# be lossy, so only defined ones are used).
printf '# caf\303\251\r\nWrite-Output "caf\303\251"\r\n' > ps1-nobom-nonascii.ps1
printf "' caf\351\r\nWScript.Echo \"caf\351\"\r\n" > vbs-nobom-nonascii.vbs
for name in ps1-nobom-nonascii.ps1 vbs-nobom-nonascii.vbs; do
  java -jar "$JSIGN_JAR" --quiet --storetype PKCS12 --keystore leaf.p12 --storepass "$pass" \
    --alg SHA-256 "$name"
  cp "$name" "$out/$name"
done

echo "script fixtures written to $out"
