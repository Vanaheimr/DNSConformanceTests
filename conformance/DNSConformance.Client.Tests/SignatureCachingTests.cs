using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 4035 §4.5 — a cached answer keeps the signatures it arrived with.
/// </summary>
/// <remarks>
/// <para>
/// "A security-aware resolver SHOULD cache each response as a single atomic entry
/// containing the entire answer, including the named RRset and any associated
/// DNSSEC RRs." The signature is part of the answer: an RRset served from the cache
/// without it is, to a validator, an RRset that was never signed.
/// </para>
/// <para>
/// The client's cache is keyed by owner name alone and merges what arrives for a
/// name into what it already holds, replacing records type by type. An RRSIG's
/// type is RRSIG whatever it covers, so two signed RRsets at one name cannot both
/// keep their signatures: the second response's RRSIG replaces the first's. Every
/// zone apex holds two signed RRsets a validator asks for — DNSKEY, and the DS the
/// parent serves for the same name — and fetches both on every chain walk.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4035 §4.5")]
public class SignatureCachingTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(800);

    private const Byte ECDSAP256SHA256 = 13;

    private static Byte[] DnskeyRdata(Byte Filler)
        => [ 0x01, 0x01, 3, ECDSAP256SHA256, .. Enumerable.Repeat(Filler, 64) ];

    private static Byte[] DsRdata(UInt16 KeyTag)
        => [ (Byte) (KeyTag >> 8), (Byte) KeyTag, ECDSAP256SHA256, 2, .. Enumerable.Repeat((Byte) 0x44, 32) ];

    /// <summary>
    /// An RRSIG over the given type at <c>example.</c>. Nothing validates it here; what
    /// matters is which type it says it covers, and that it is still there afterwards.
    /// </summary>
    private static Byte[] RrsigRdata(UInt16 TypeCovered, UInt16 KeyTag, String Signer)
    {

        var expiration = (UInt32) DateTimeOffset.UtcNow.AddDays(14).ToUnixTimeSeconds();
        var inception  = (UInt32) DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds();

        return [
            (Byte) (TypeCovered >> 8), (Byte) TypeCovered,
            ECDSAP256SHA256,
            1,                                                              // labels
            0x00, 0x00, 0x0E, 0x10,                                         // original TTL 3600
            (Byte) (expiration >> 24), (Byte) (expiration >> 16), (Byte) (expiration >> 8), (Byte) expiration,
            (Byte) (inception  >> 24), (Byte) (inception  >> 16), (Byte) (inception  >> 8), (Byte) inception,
            (Byte) (KeyTag >> 8), (Byte) KeyTag,
            .. RawDnsWriter.NameBytes(Signer),
            .. Enumerable.Repeat((Byte) 0x5A, 64)
        ];

    }

    /// <summary>
    /// The apex of a signed zone, as a recursive resolver serves it: the DNSKEY RRset
    /// signed by the zone itself, the DS RRset signed by the parent.
    /// </summary>
    private static ScriptedUdpServer SignedApex()

        => new (request => {

               var question = RawDnsReader.Parse(request).Questions.Single();

               return question.Type switch {

                   RawDnsType.DNSKEY => RawDnsResponder.Answer(request,
                                            ("example.", RawDnsType.DNSKEY, 3600, DnskeyRdata(0x11)),
                                            ("example.", RawDnsType.RRSIG,  3600, RrsigRdata(RawDnsType.DNSKEY, 1111, "example."))),

                   RawDnsType.DS     => RawDnsResponder.Answer(request,
                                            ("example.", RawDnsType.DS,     3600, DsRdata(1111)),
                                            ("example.", RawDnsType.RRSIG,  3600, RrsigRdata(RawDnsType.DS,     2222, "."))),

                   _                 => RawDnsResponder.Rcode(request, 0)

               };

           });

    private static Int32 QuestionsOfType(ScriptedUdpServer Server, UInt16 Type)
        => Server.Requests.
               Count(request => RawDnsReader.Parse(request).Questions.Any(question => question.Type == Type));

    #endregion


    #region A_Cached_RRset_Keeps_Its_Signature_When_Another_Signed_RRset_Arrives_For_The_Same_Name()

    /// <summary>
    /// DNSKEY first, DS second, DNSKEY again — the order of every chain walk that
    /// crosses a zone apex and the order a second validation repeats. The third
    /// question is answered from the cache, and must be answered with its signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without it the validator's walk takes the branch for "the parent does not
    /// sign its DNSKEY RRset" and answers Insecure. That is what was observed live:
    /// the TLSA records of <c>_25._tcp.mail.sys4.de</c> validated Secure with the
    /// cache off and Insecure with it on, as soon as anything else under
    /// <c>sys4.de</c> had been validated first and had put the DNSKEY and DS of
    /// <c>de.</c> into the cache in this order.
    /// </para>
    /// <para>
    /// For DANE an Insecure TLSA RRset is not an error but an instruction: RFC 7672
    /// §2.2 uses TLSA records only when they are secure, so the client falls back
    /// to unauthenticated opportunistic TLS — the downgrade DANE exists to prevent,
    /// caused here by the resolver's own cache rather than by an attacker.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "4035 §4.5, 7672 §2.2")]
    public async Task A_Cached_RRset_Keeps_Its_Signature_When_Another_Signed_RRset_Arrives_For_The_Same_Name()
    {

        await using var server = SignedApex();

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  true
                           );

        var first  = await client.Query(DNSServiceName.Parse("example."), [ DNSResourceRecordTypes.DNSKEY ], ShortTimeout);
        var ds     = await client.Query(DNSServiceName.Parse("example."), [ DNSResourceRecordTypes.DS     ], ShortTimeout);
        var again  = await client.Query(DNSServiceName.Parse("example."), [ DNSResourceRecordTypes.DNSKEY ], ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(first.Answers.OfType<RRSIG>().Count(sig => sig.TypeCovered == DNSResourceRecordTypes.DNSKEY), Is.EqualTo(1),
                        "control: the DNSKEY RRset arrived signed");

            Assert.That(ds.   Answers.OfType<RRSIG>().Count(sig => sig.TypeCovered == DNSResourceRecordTypes.DS),     Is.EqualTo(1),
                        "control: the DS RRset arrived signed");

            Assert.That(QuestionsOfType(server, RawDnsType.DNSKEY), Is.EqualTo(1),
                        "control: the second DNSKEY question was answered from the cache, which is what is being examined");

        });

        Assert.Multiple(() => {

            Assert.That(again.Answers.OfType<DNSKEY>().Count(), Is.EqualTo(1),
                        "the cached DNSKEY RRset is served");

            Assert.That(again.Answers.OfType<RRSIG>().Count(sig => sig.TypeCovered == DNSResourceRecordTypes.DNSKEY), Is.EqualTo(1),
                        "and served with the signature it arrived with — RFC 4035 §4.5's atomic entry");

        });

    }

    #endregion

}
