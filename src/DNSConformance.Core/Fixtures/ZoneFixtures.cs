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

}
