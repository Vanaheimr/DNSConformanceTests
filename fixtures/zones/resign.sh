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

# Flatten to exactly one record per line: the multi-line parenthesized form
# BIND emits is awkward to consume from tests, and the flat form is what the
# fixture loader reads.
named-compilezone -f text -F text -o "$ZONE.zone.flat" "$ZONE" "$ZONE.zone.signed" > /dev/null 2>&1

# dnssec-signzone also writes "dsset-<zone>." — a trailing dot in a filename is
# illegal on Windows and breaks git on this checkout. The DS record is already
# in "$ZONE.ds", so drop it.
rm -f "dsset-$ZONE."


# ---------------------------------------------------------------------------
# One separately signed zone per signature algorithm Hermod claims to verify.
#
# These are not redundant with the RSASHA256 zone above. Each algorithm family
# has its own key and signature encoding, and those encodings are where
# implementations actually break: RSA carries its exponent in the two forms of
# RFC 3110, ECDSA is a fixed-width r||s pair rather than an ASN.1 sequence, and
# the Edwards curves are raw 32- and 57-octet keys. A verifier can handle one
# family perfectly and be entirely broken for the next.
#
# Algorithms that this BIND cannot sign with are skipped rather than aborting
# the run: the matching test then reports the fixture as missing and ignores
# itself, which keeps a bare checkout green.
# ---------------------------------------------------------------------------
sign_algorithm_zone() {

    zone="$1"      # zone name
    algo="$2"      # dnssec-keygen algorithm name
    bits="$3"      # key size flags, empty for the curve algorithms
    label="$4"     # human-readable, goes into the zone's TXT record
    extra="$5"     # extra dnssec-signzone flags, e.g. "-3 aabbccdd" for NSEC3
    records="$6"   # extra zone records, appended verbatim

    cat > "$zone.zone" <<EOF
\$TTL 3600
@       IN  SOA ns1.$zone. hostmaster.$zone. (
                2026072501 ; serial
                7200       ; refresh
                3600       ; retry
                1209600    ; expire
                3600 )     ; minimum
@       IN  NS   ns1.$zone.
ns1     IN  A    192.0.2.54
a       IN  A    192.0.2.13
aaaa    IN  AAAA 2001:db8::13
txt     IN  TXT  "signed by BIND with $label"
*.wild  IN  A    192.0.2.77
$records
EOF

    # shellcheck disable=SC2086
    ksk=$(dnssec-keygen -a "$algo" $bits -f KSK -n ZONE "$zone" 2>/dev/null) || {
        echo "  skipped $zone: $algo key generation unsupported"
        rm -f "$zone.zone"
        return 0
    }

    # shellcheck disable=SC2086
    zsk=$(dnssec-keygen -a "$algo" $bits -n ZONE "$zone" 2>/dev/null)

    # shellcheck disable=SC2086
    if ! dnssec-signzone -o "$zone" -N INCREMENT -S -x -t $extra "$zone.zone" > "signing-$zone.log" 2>&1; then
        # shellcheck disable=SC2086
        if ! dnssec-signzone -o "$zone" -k "$ksk" $extra "$zone.zone" "$zsk" > "signing-$zone.log" 2>&1; then
            echo "  skipped $zone: $algo signing refused (see signing-$zone.log)"
            rm -f "$zone.zone" "K$zone."*
            return 0
        fi
    fi

    dnssec-dsfromkey -2 "$ksk.key" > "$zone.ds"
    named-compilezone -f text -F text -o "$zone.zone.flat" "$zone" "$zone.zone.signed" > /dev/null 2>&1
    rm -f "dsset-$zone."

    echo "  signed  $zone with $algo"

}

echo "signing one zone per algorithm:"

# 13 — ECDSA P-256. Keeps its historical zone name, since tests already use it.
sign_algorithm_zone "ecdsa.$ZONE"     ECDSAP256SHA256  ""          "ECDSA P-256"

# 14 — ECDSA P-384: same r||s convention, different curve and digest size.
sign_algorithm_zone "ecdsap384.$ZONE" ECDSAP384SHA384  ""          "ECDSA P-384"

# 15 / 16 — the Edwards curves (RFC 8080), verified through BouncyCastle.
sign_algorithm_zone "ed25519.$ZONE"   ED25519          ""          "Ed25519"
sign_algorithm_zone "ed448.$ZONE"     ED448            ""          "Ed448"

# 10 — RSA/SHA-512: same RFC 3110 key encoding as RSASHA256, different digest.
sign_algorithm_zone "rsasha512.$ZONE" RSASHA512        "-b 2048"   "RSA/SHA-512"

# 5 / 7 — RSA/SHA-1. RFC 8624 says these MUST NOT be used for new signatures but
# MAY still be validated, and zones signed with them are still out there, so the
# validation path is worth covering. Modern BIND often refuses to sign with them,
# in which case these are skipped.
sign_algorithm_zone "rsasha1.$ZONE"   RSASHA1          "-b 2048"   "RSA/SHA-1"
sign_algorithm_zone "nsec3rsasha1.$ZONE" NSEC3RSASHA1  "-b 2048"   "RSA/SHA-1 (NSEC3)"

# A zone actually signed with NSEC3, which none of the above are: the names
# ending in "nsec3rsasha1" refer to the *signature* algorithm, and BIND emits
# plain NSEC unless it is told otherwise. Authenticated denial of existence over
# NSEC3 needs a chain of hashed owner names to walk, so it needs this zone.
#
# Salt and iterations match the RFC 5155 Appendix A example, so a hash computed
# here can be checked against the published vectors as well as against BIND.
sign_algorithm_zone "nsec3.$ZONE"     RSASHA256        "-b 2048"   "RSASHA256 (NSEC3)"  "-3 aabbccdd -H 12"

# And one signed with NSEC3 opt-out (-A), holding an unsigned delegation.
#
# Opt-out is the part of RFC 5155 that cannot be tested with a zone alone: §6
# lets a signer skip the NSEC3 records for insecure delegations, so what a
# server has to send for one (§7.2.7) is a closest encloser proof whose covering
# record carries the Opt-Out flag — and there has to *be* an insecure delegation
# for any of that to exist. "insecure.optout.dnssec.test" is that delegation:
# NS records and glue, no DS, and — because of -A — no NSEC3 of its own.
sign_algorithm_zone "optout.$ZONE"    RSASHA256        "-b 2048"   "RSASHA256 (NSEC3 opt-out)"  "-3 aabbccdd -H 12 -A"  \
"insecure      IN  NS   ns1.insecure
ns1.insecure  IN  A    192.0.2.90"

# A zone holding a DNAME, so that the redirection can be checked by something
# that did not perform it.
#
# RFC 6672 §3.1 leaves the synthesized CNAME unsigned — the server invents it
# while answering, so there is nothing to have signed it. What a validator
# authenticates is the DNAME, and it then derives the CNAME for itself; a test
# that only looked at the answer section could not tell that apart from a
# server that simply forgot to sign one record.
#
# "redirect" is a sibling of "target" rather than above it, because RFC 6672
# §2.4 forbids records below a DNAME owner and BIND is right to refuse a zone
# that has them.
sign_algorithm_zone "dname.$ZONE"     RSASHA256        "-b 2048"   "RSASHA256 (DNAME)"  "" \
"redirect     IN  DNAME  target.dname.$ZONE.
host.target  IN  A      192.0.2.14"

echo
echo "signed zones written to $OUT"
ls -1 "$OUT"
