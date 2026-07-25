#!/bin/sh
#
# Regenerate the DNSSEC fixtures used by DNSConformance.Dnssec.Tests.
#
# The signed zone is produced by BIND's dnssec-signzone — an independent
# implementation — so that Hermod's RRSIG validation is measured against
# signatures it did not create itself.
#
# Requires: bind9 / bind9utils (dnssec-keygen, dnssec-signzone)
# Usage:    wsl -e sh fixtures/zones/resign.sh
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/signed"
ZONE="dnssec.test"

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

cat > "$ZONE.zone" <<EOF
\$TTL 3600
@       IN  SOA ns1.$ZONE. hostmaster.$ZONE. (
                2026072501 ; serial
                7200       ; refresh
                3600       ; retry
                1209600    ; expire
                3600 )     ; minimum
@       IN  NS   ns1.$ZONE.
ns1     IN  A    192.0.2.53
a       IN  A    192.0.2.1
aaaa    IN  AAAA 2001:db8::1
mx      IN  MX   10 mail.$ZONE.
mail    IN  A    192.0.2.25
txt     IN  TXT  "signed by BIND"
*.wild  IN  A    192.0.2.77
EOF

# RSASHA256 (algorithm 8) — the most widely deployed algorithm, and the one
# used by the IANA root KSK, so the same code path as real-world validation.
KSK=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK -n ZONE "$ZONE")
ZSK=$(dnssec-keygen -a RSASHA256 -b 1024        -n ZONE "$ZONE")

dnssec-signzone -o "$ZONE" -N INCREMENT -S -x -t "$ZONE.zone" > signing.log 2>&1 || \
dnssec-signzone -o "$ZONE" -k "$KSK" "$ZONE.zone" "$ZSK" > signing.log 2>&1

# The DS record of the KSK, i.e. what the parent zone would publish.
dnssec-dsfromkey -2 "$KSK.key" > "$ZONE.ds"

# ---------------------------------------------------------------------------
# A second, separately signed zone using ECDSAP256SHA256 (algorithm 13) — the
# modern default, and a completely different verification path from RSA. This
# zone is actually signed, not merely key-generated, so the tests have real
# ECDSA signatures to check.
# ---------------------------------------------------------------------------
EC_ZONE="ecdsa.$ZONE"

cat > "$EC_ZONE.zone" <<EOF
\$TTL 3600
@       IN  SOA ns1.$EC_ZONE. hostmaster.$EC_ZONE. (
                2026072501 ; serial
                7200       ; refresh
                3600       ; retry
                1209600    ; expire
                3600 )     ; minimum
@       IN  NS   ns1.$EC_ZONE.
ns1     IN  A    192.0.2.54
a       IN  A    192.0.2.13
txt     IN  TXT  "signed by BIND with ECDSA P-256"
EOF

EC_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE "$EC_ZONE")
EC_ZSK=$(dnssec-keygen -a ECDSAP256SHA256        -n ZONE "$EC_ZONE")

dnssec-signzone -o "$EC_ZONE" -N INCREMENT -S -x -t "$EC_ZONE.zone" > signing-ecdsa.log 2>&1 || \
dnssec-signzone -o "$EC_ZONE" -k "$EC_KSK" "$EC_ZONE.zone" "$EC_ZSK" > signing-ecdsa.log 2>&1

dnssec-dsfromkey -2 "$EC_KSK.key" > "$EC_ZONE.ds"

# Flatten to exactly one record per line: the multi-line parenthesized form
# BIND emits is awkward to consume from tests, and the flat form is what the
# fixture loader reads.
named-compilezone -f text -F text -o "$ZONE.zone.flat"    "$ZONE"    "$ZONE.zone.signed"    > /dev/null 2>&1
named-compilezone -f text -F text -o "$EC_ZONE.zone.flat" "$EC_ZONE" "$EC_ZONE.zone.signed" > /dev/null 2>&1

# dnssec-signzone also writes "dsset-<zone>." — a trailing dot in a filename is
# illegal on Windows and breaks git on this checkout. The DS records are already
# in "$ZONE.ds" / "$EC_ZONE.ds", so drop them.
rm -f "dsset-$ZONE." "dsset-$EC_ZONE."

echo "signed zone written to $OUT"
ls -1 "$OUT"
