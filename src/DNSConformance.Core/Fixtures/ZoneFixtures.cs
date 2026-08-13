using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// The standard authoritative test zone <c>conformance.test.</c> used by
/// server conformance and interop tests. All expected values are exposed as
/// constants so raw-socket assertions and external tools (dig/kdig/drill)
/// check against the same truth.
/// </summary>
public static class ZoneFixtures
{

    public const String Origin           = "conformance.test.";

    public const String NameServer       = "ns1.conformance.test.";
    public const String NameServerIPv4   = "192.0.2.53";

    public const String AName            = "a.conformance.test.";
    public const String AAddress         = "192.0.2.1";

    public const String MultiName        = "multi.conformance.test.";
    public static readonly String[] MultiAddresses = ["192.0.2.10", "192.0.2.11", "192.0.2.12"];

    public const String QuadAName        = "aaaa.conformance.test.";
    public const String QuadAAddress     = "2001:db8::1";

    public const String CNameAlias       = "alias.conformance.test.";
    public const String CNameAlias2      = "alias2.conformance.test.";

    public const String MxName           = "mx.conformance.test.";
    public const String Mail1            = "mail1.conformance.test.";
    public const String Mail2            = "mail2.conformance.test.";

    public const String TxtName          = "txt.conformance.test.";
    public const String TxtValue         = "Hello DNS conformance!";

    public const String BigTxtName       = "big.conformance.test.";
    public static readonly String BigTxtValue = new('x', 600);   // forces >1 character-string (RFC 1035 §3.3.14)

    public const String SrvName          = "_dns._udp.conformance.test.";
    public const UInt16 SrvPriority      = 10;
    public const UInt16 SrvWeight        = 60;
    public const UInt16 SrvPort          = 5353;

    public const String CaaName          = "caa.conformance.test.";
    public const String CaaValue         = "letsencrypt.org";

    public const String SshfpName        = "ssh.conformance.test.";

    public const String HinfoName        = "hinfo.conformance.test.";

    public const String SpfName          = "spf.conformance.test.";
    public const String SpfValue         = "v=spf1 -all";

    public const String DnameName        = "dname.conformance.test.";
    public const String DnameTarget      = "target.conformance.test.";

    public const String PtrName          = "42.2.0.192.in-addr.arpa.";

    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);


    /// <summary>Build the standard zone in memory.</summary>
    public static InMemoryDNSZone CreateStandardZone()
    {

        var ttl  = DefaultTtl;
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                DomainName.Parse(Origin),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(NameServer),
                SimpleEMailAddress.Parse("hostmaster@conformance.test"),
                2026072501,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS(
                DomainName.Parse(Origin),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(NameServer)
            ),

            new A   (DomainName.Parse(NameServer), DNSQueryClasses.IN, ttl, IPv4Address.Parse(NameServerIPv4)),
            new A   (DomainName.Parse(AName),      DNSQueryClasses.IN, ttl, IPv4Address.Parse(AAddress)),

            new A   (DomainName.Parse(MultiName),  DNSQueryClasses.IN, ttl, IPv4Address.Parse(MultiAddresses[0])),
            new A   (DomainName.Parse(MultiName),  DNSQueryClasses.IN, ttl, IPv4Address.Parse(MultiAddresses[1])),
            new A   (DomainName.Parse(MultiName),  DNSQueryClasses.IN, ttl, IPv4Address.Parse(MultiAddresses[2])),

            new AAAA(DomainName.Parse(QuadAName),  DNSQueryClasses.IN, ttl, IPv6Address.Parse(QuadAAddress)),

            new CNAME(
                DomainName.Parse(CNameAlias),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(AName)
            ),

            new CNAME(
                DomainName.Parse(CNameAlias2),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(CNameAlias)
            ),

            new MX  (DomainName.Parse(MxName), DNSQueryClasses.IN, ttl, 10, DomainName.Parse(Mail1)),
            new MX  (DomainName.Parse(MxName), DNSQueryClasses.IN, ttl, 20, DomainName.Parse(Mail2)),
            new A   (DomainName.Parse(Mail1),  DNSQueryClasses.IN, ttl, IPv4Address.Parse("192.0.2.25")),
            new A   (DomainName.Parse(Mail2),  DNSQueryClasses.IN, ttl, IPv4Address.Parse("192.0.2.26")),

            new TXT (DomainName.Parse(TxtName),    DNSQueryClasses.IN, ttl, TxtValue),
            new TXT (DomainName.Parse(BigTxtName), DNSQueryClasses.IN, ttl, BigTxtValue),

            new SRV (
                DNSServiceName.Parse(SrvName),
                DNSQueryClasses.IN,
                ttl,
                SrvPriority,
                SrvWeight,
                IPPort.Parse(SrvPort),
                DomainName.Parse(NameServer)
            ),

            new PTR (
                DomainName.Parse(PtrName),
                DNSQueryClasses.IN,
                ttl,
                DNSServiceName.Parse(AName)
            ),

            new CAA (DomainName.Parse(CaaName), DNSQueryClasses.IN, ttl, 0, "issue", CaaValue),

            new SSHFP(
                DomainName.Parse(SshfpName),
                DNSQueryClasses.IN,
                ttl,
                SSHFP_Algorithm.RSA,
                SSHFP_FingerprintType.SHA256,
                Convert.FromHexString("123456789abcdef67890123456789abcdef67890123456789abcdef123456789".AsSpan(0, 64))
            ),

            new HINFO(DomainName.Parse(HinfoName), DNSQueryClasses.IN, ttl, "VAX-11/780", "UNIX"),

            new SPF  (DomainName.Parse(SpfName),   DNSQueryClasses.IN, ttl, SpfValue),

            new DNAME(
                DomainName.Parse(DnameName),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(DnameTarget)
            )

        );

        return zone;

    }


    #region The wildcard / delegation zone (RFC 4592, RFC 1034 §4.3.2)

    public const String WildOrigin        = "wild.test.";
    public const String WildNameServer    = "ns1.wild.test.";

    /// <summary>The wildcard at the apex: <c>*.wild.test.</c></summary>
    public const String WildcardAddress   = "192.0.2.100";
    public const String WildcardMailHost  = "mail.wild.test.";

    /// <summary>A name that exists, so the wildcard must not answer for it.</summary>
    public const String WildExactName     = "sub.wild.test.";
    public const String WildExactAddress  = "192.0.2.1";

    /// <summary>Below <c>sub</c>, which is the closest encloser — and holds no wildcard of its own.</summary>
    public const String WildBelowExact    = "nothing.sub.wild.test.";

    /// <summary>An empty non-terminal: no records, but a name below it has some.</summary>
    public const String WildEmptyName     = "empty.wild.test.";
    public const String WildBelowEmpty    = "x.empty.wild.test.";
    public const String WildBelowEmptyTxt = "the name above me exists";

    /// <summary>A delegation, with in-subtree glue.</summary>
    public const String WildDelegation    = "child.wild.test.";
    public const String WildChildNS       = "ns1.child.wild.test.";
    public const String WildChildGlue     = "192.0.2.200";


    /// <summary>
    /// A zone built to ask the wildcard questions RFC 4592 cares about: a
    /// wildcard at the apex, a name that must beat it, a name *below* that name
    /// which must not reach past it, an empty non-terminal the wildcard must not
    /// apply to, and a delegation.
    /// </summary>
    public static InMemoryDNSZone CreateWildcardZone()
    {

        var ttl  = DefaultTtl;
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                DomainName.Parse(WildOrigin),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(WildNameServer),
                SimpleEMailAddress.Parse("hostmaster@wild.test"),
                2026081301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS  (DomainName.Parse(WildOrigin),     DNSQueryClasses.IN, ttl, DomainName.Parse(WildNameServer)),
            new A   (DomainName.Parse(WildNameServer), DNSQueryClasses.IN, ttl, IPv4Address.Parse("192.0.2.53")),

            // The wildcard itself. ParseLenient, because '*' is not a hostname
            // label and the strict parser is right to refuse it everywhere else.
            new A   (DomainName.ParseLenient("*." + WildOrigin), DNSQueryClasses.IN, ttl, IPv4Address.Parse(WildcardAddress)),
            new MX  (DomainName.ParseLenient("*." + WildOrigin), DNSQueryClasses.IN, ttl, 10, DomainName.Parse(WildcardMailHost)),

            new A   (DomainName.Parse(WildExactName),  DNSQueryClasses.IN, ttl, IPv4Address.Parse(WildExactAddress)),

            new TXT (DomainName.Parse(WildBelowEmpty), DNSQueryClasses.IN, ttl, WildBelowEmptyTxt),

            new NS  (DomainName.Parse(WildDelegation), DNSQueryClasses.IN, ttl, DomainName.Parse(WildChildNS)),
            new A   (DomainName.Parse(WildChildNS),    DNSQueryClasses.IN, ttl, IPv4Address.Parse(WildChildGlue))

        );

        return zone;

    }

    #endregion

    #region The DNAME zone (RFC 6672)

    public const String DNameOrigin       = "dname.test.";
    public const String DNameNameServer   = "ns1.dname.test.";

    /// <summary>A DNAME whose target is in the same zone, so a query can be followed to the end.</summary>
    public const String DNameOwner        = "alias.dname.test.";
    public const String DNameTarget       = "target.dname.test.";

    /// <summary>Data <i>at</i> the DNAME owner. RFC 6672 §2.3 leaves the owner name itself unredirected.</summary>
    public const String DNameOwnerMail    = "mail.dname.test.";

    /// <summary>One label below the DNAME: <c>host.alias</c> → <c>host.target</c>.</summary>
    public const String DNameQueried      = "host.alias.dname.test.";
    public const String DNameResolved     = "host.target.dname.test.";
    public const String DNameAddress      = "192.0.2.10";

    /// <summary>Several labels below it — the whole prefix is carried over, not just one label.</summary>
    public const String DNameDeepQueried  = "a.b.c.alias.dname.test.";
    public const String DNameDeepResolved = "a.b.c.target.dname.test.";
    public const String DNameDeepAddress  = "192.0.2.11";

    /// <summary>
    /// A record below the DNAME owner, which RFC 6672 §2.4 says must not exist:
    /// "Resource records MUST NOT exist at any subdomain of the owner of a DNAME
    /// RR." It is here so that the occlusion is observable — a server that
    /// answered from it would be preferring a record the zone should not contain
    /// over the redirection the zone does contain.
    /// </summary>
    public const String DNameOccluded     = "occluded.alias.dname.test.";
    public const String DNameOccludedAddr = "192.0.2.66";

    /// <summary>A DNAME pointing out of the zone, which is the ordinary case.</summary>
    public const String DNameForeignOwner = "away.dname.test.";
    public const String DNameForeign      = "elsewhere.example.";

    /// <summary>A name beside the DNAME, which nothing may redirect.</summary>
    public const String DNameSibling      = "other.dname.test.";
    public const String DNameSiblingAddr  = "192.0.2.12";

    /// <summary>
    /// A DNAME whose target is long enough that the substitution runs into the
    /// 255-octet limit — four labels of 60, i.e. 245 octets on the wire.
    /// </summary>
    /// <remarks>
    /// A one-label prefix adds 1 + its length, so a prefix of 9 characters lands
    /// on exactly 255 and one of 10 goes over. RFC 6672 §2.2 answers the second
    /// with YXDOMAIN, and the pair is what pins the boundary to the octet rather
    /// than to somewhere near it.
    /// </remarks>
    public const String DNameLongOwner    = "long.dname.test.";
    public static readonly String DNameLongTarget =
        new String('a', 60) + "." + new String('b', 60) + "." +
        new String('c', 60) + "." + new String('d', 60) + ".";

    /// <summary>A DNAME pointing into its own subtree: every pass produces a longer name.</summary>
    public const String DNameLoopOwner    = "loop.dname.test.";
    public const String DNameLoopTarget   = "sub.loop.dname.test.";


    /// <summary>
    /// A zone built to ask what RFC 6672 actually requires of a server: which
    /// names a DNAME redirects, which it leaves alone, what the answer carries,
    /// and what happens when the rewritten name will not fit.
    /// </summary>
    public static InMemoryDNSZone CreateDNameZone()
    {

        var ttl  = DefaultTtl;
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                DomainName.Parse(DNameOrigin),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(DNameNameServer),
                SimpleEMailAddress.Parse("hostmaster@dname.test"),
                2026081301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS   (DomainName.Parse(DNameOrigin),     DNSQueryClasses.IN, ttl, DomainName.Parse(DNameNameServer)),
            new A    (DomainName.Parse(DNameNameServer), DNSQueryClasses.IN, ttl, IPv4Address.Parse("192.0.2.53")),

            new DNAME(DomainName.Parse(DNameOwner),      DNSQueryClasses.IN, ttl, DomainName.Parse(DNameTarget)),

            // Beside the DNAME at the same name — legal, and the proof that the
            // owner is not itself redirected.
            new MX   (DomainName.Parse(DNameOwner),      DNSQueryClasses.IN, ttl, 10, DomainName.Parse(DNameOwnerMail)),
            new A    (DomainName.Parse(DNameOwnerMail),  DNSQueryClasses.IN, ttl, IPv4Address.Parse("192.0.2.25")),

            new A    (DomainName.Parse(DNameResolved),     DNSQueryClasses.IN, ttl, IPv4Address.Parse(DNameAddress)),
            new A    (DomainName.Parse(DNameDeepResolved), DNSQueryClasses.IN, ttl, IPv4Address.Parse(DNameDeepAddress)),

            new A    (DomainName.Parse(DNameOccluded),    DNSQueryClasses.IN, ttl, IPv4Address.Parse(DNameOccludedAddr)),

            new DNAME(DomainName.Parse(DNameForeignOwner), DNSQueryClasses.IN, ttl, DomainName.Parse(DNameForeign)),

            new A    (DomainName.Parse(DNameSibling),      DNSQueryClasses.IN, ttl, IPv4Address.Parse(DNameSiblingAddr)),

            new DNAME(DomainName.Parse(DNameLongOwner),    DNSQueryClasses.IN, ttl, DomainName.Parse(DNameLongTarget)),

            new DNAME(DomainName.Parse(DNameLoopOwner),    DNSQueryClasses.IN, ttl, DomainName.Parse(DNameLoopTarget))

        );

        return zone;

    }

    #endregion

    #region The opaque zone (RFC 3597)

    public const String OpaqueOrigin      = "opaque.test.";
    public const String OpaqueNameServer  = "ns1.opaque.test.";

    /// <summary>
    /// Type codes with no parser in this build. 65280–65534 is the IANA
    /// private-use range, which is where a type that will never be allocated
    /// belongs — a currently-unassigned code from the ordinary range would stop
    /// being unknown the day IANA assigns it.
    /// </summary>
    public const UInt16 OpaqueType        = 65280;
    public const UInt16 OpaqueSecondType  = 65281;
    public const UInt16 OpaquePointerType = 65282;

    /// <summary>A name holding two records of one unknown type, i.e. an RRset.</summary>
    public const String OpaqueName        = "weird.opaque.test.";
    public static readonly Byte[] OpaqueRData1 = [ 0xDE, 0xAD, 0xBE, 0xEF ];
    public static readonly Byte[] OpaqueRData2 = [ 0x00, 0x01, 0x02, 0x03, 0x04 ];

    /// <summary>A name holding both a known and an unknown type.</summary>
    public const String OpaqueMixedName    = "mixed.opaque.test.";
    public const String OpaqueMixedAddress = "192.0.2.5";
    public static readonly Byte[] OpaqueMixedRData = [ 0xC0, 0xFF, 0xEE ];

    /// <summary>
    /// RDATA that is a valid RFC 1035 §4.1.4 compression pointer to offset 12 —
    /// the first byte after the header, where the question name begins.
    /// </summary>
    /// <remarks>
    /// Nothing may act on that. RFC 3597 §4 forbids writing such a pointer into
    /// the RDATA of a type that is not well-known, and §2 leaves a receiver no
    /// way to know one is there — so these two octets have to arrive as two
    /// octets. An implementation that "helpfully" expands them turns three bytes
    /// of RDATA into a name, and one that rewrites them on the way out points at
    /// whatever happens to sit at offset 12 of the new message.
    /// </remarks>
    public const String OpaquePointerName  = "pointerish.opaque.test.";
    public static readonly Byte[] OpaquePointerRData = [ 0xC0, 0x0C ];

    /// <summary>An unknown type behind a wildcard, so synthesis has to copy RDATA it cannot read.</summary>
    public const String OpaqueWildcardName = "anything.wild.opaque.test.";
    public static readonly Byte[] OpaqueWildcardRData = [ 0x2A, 0x2A, 0x2A ];


    /// <summary>
    /// A zone whose interesting records this build has no parser for (RFC 3597).
    /// </summary>
    /// <remarks>
    /// The point of the zone is that the server has to do its job without
    /// understanding its contents: store the records, pick the right ones for a
    /// question, synthesise one from a wildcard, and put the RDATA back on the
    /// wire exactly as it came in — all by the outer shape of a record alone.
    /// </remarks>
    public static InMemoryDNSZone CreateOpaqueZone()
    {

        var ttl  = DefaultTtl;
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                DomainName.Parse(OpaqueOrigin),
                DNSQueryClasses.IN,
                ttl,
                DomainName.Parse(OpaqueNameServer),
                SimpleEMailAddress.Parse("hostmaster@opaque.test"),
                2026081301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS  (DomainName.Parse(OpaqueOrigin),     DNSQueryClasses.IN, ttl, DomainName.Parse(OpaqueNameServer)),
            new A   (DomainName.Parse(OpaqueNameServer), DNSQueryClasses.IN, ttl, IPv4Address.Parse("192.0.2.53")),

            new UnknownRecord(DomainName.Parse(OpaqueName),         (DNSResourceRecordTypes) OpaqueType,        DNSQueryClasses.IN, ttl, OpaqueRData1),
            new UnknownRecord(DomainName.Parse(OpaqueName),         (DNSResourceRecordTypes) OpaqueType,        DNSQueryClasses.IN, ttl, OpaqueRData2),

            new A            (DomainName.Parse(OpaqueMixedName),                                                DNSQueryClasses.IN, ttl, IPv4Address.Parse(OpaqueMixedAddress)),
            new UnknownRecord(DomainName.Parse(OpaqueMixedName),    (DNSResourceRecordTypes) OpaqueSecondType,  DNSQueryClasses.IN, ttl, OpaqueMixedRData),

            new UnknownRecord(DomainName.Parse(OpaquePointerName),  (DNSResourceRecordTypes) OpaquePointerType, DNSQueryClasses.IN, ttl, OpaquePointerRData),

            new UnknownRecord(DomainName.ParseLenient("*.wild." + OpaqueOrigin), (DNSResourceRecordTypes) OpaqueType, DNSQueryClasses.IN, ttl, OpaqueWildcardRData)

        );

        return zone;

    }

    #endregion

}
