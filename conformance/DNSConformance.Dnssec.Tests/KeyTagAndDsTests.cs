using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 Appendix B (key tag) and §5.1.4 / RFC 4509 (DS digest) —
/// checked against published, independently verifiable values.
/// </summary>
[TestFixture]
[Property("RFC", "4034")]
public class KeyTagAndDsTests
{

    /// <summary>
    /// The IANA root KSK-2017 (key tag 20326), published in the DNSSEC root
    /// trust anchor XML and in every resolver's built-in anchor set.
    /// </summary>
    private const String RootKsk2017Base64 =
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";

    /// <summary>
    /// The DS digest published for KSK-2017 (algorithm 8, digest type 2 = SHA-256).
    /// </summary>
    private const String RootKsk2017DsSha256 =
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";


    private static DNSKEY RootKsk2017()
        => new(
               DomainName.Parse("."),
               DNSQueryClasses.IN,
               TimeSpan.FromDays(1),
               257,                                     // ZONE | SEP
               3,
               8,                                       // RSASHA256
               Convert.FromBase64String(RootKsk2017Base64)
           );


    #region KeyTag_Of_The_IANA_Root_Ksk_Is_20326()

    [Test]
    [Property("RFC", "4034 App. B")]
    public void KeyTag_Of_The_IANA_Root_Ksk_Is_20326()
    {

        // The best-known key tag in the DNS: every validating resolver on the
        // planet computes 20326 for this key.
        Assert.That(DNSSECValidator.ComputeKeyTag(RootKsk2017()), Is.EqualTo((UInt16) 20326));

    }

    #endregion

    #region Ds_Digest_Of_The_IANA_Root_Ksk_Matches_The_Published_Anchor()

    [Test]
    [Property("RFC", "4034 §5.1.4")]
    public void Ds_Digest_Of_The_IANA_Root_Ksk_Matches_The_Published_Anchor()
    {

        // digest = SHA-256( canonical owner name | DNSKEY RDATA )
        var trustAnchor = new DS(
                              DomainName.Parse("."),
                              DNSQueryClasses.IN,
                              TimeSpan.FromDays(1),
                              20326,
                              8,
                              2,
                              Bytes.FromHex(RootKsk2017DsSha256)
                          );

        Assert.That(DNSSECValidator.VerifyDS(RootKsk2017(), trustAnchor), Is.True,
                    "the computed DS digest must match IANA's published root anchor");

    }

    #endregion

    #region Ds_Verification_Rejects_A_Tampered_Digest()

    [Test]
    public void Ds_Verification_Rejects_A_Tampered_Digest()
    {

        var digest     = Bytes.FromHex(RootKsk2017DsSha256);
        digest[0]     ^= 0xFF;

        var tampered   = new DS(DomainName.Parse("."), DNSQueryClasses.IN, TimeSpan.FromDays(1), 20326, 8, 2, digest);

        Assert.That(DNSSECValidator.VerifyDS(RootKsk2017(), tampered), Is.False);

    }

    #endregion

    #region Ds_Verification_Rejects_An_Unknown_Digest_Type()

    [Test]
    [Property("RFC", "4034 §5.1.3")]
    public void Ds_Verification_Rejects_An_Unknown_Digest_Type()
    {

        // Digest type 99 is unassigned — an unknown algorithm must not
        // accidentally validate.
        var unknown = new DS(
                          DomainName.Parse("."),
                          DNSQueryClasses.IN,
                          TimeSpan.FromDays(1),
                          20326,
                          8,
                          99,
                          Bytes.FromHex(RootKsk2017DsSha256)
                      );

        Assert.That(DNSSECValidator.VerifyDS(RootKsk2017(), unknown), Is.False);

    }

    #endregion

    #region KeyTag_Is_Stable_Under_Reserialization()

    [Test]
    public void KeyTag_Is_Stable_Under_Reserialization()
    {

        // The key tag is computed over the DNSKEY RDATA, so it must survive a
        // wire round-trip untouched.
        var original  = RootKsk2017();

        var ms        = new MemoryStream();
        ms.Write(new Byte[12]);
        original.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        var wire      = ms.ToArray();
        wire[6] = 0; wire[7] = 1;                    // ANCOUNT = 1

        var decoded   = Core.RawDns.RawDnsReader.Parse(wire).Answers.Single();

        var reparsed  = new DNSKEY(
                            DomainName.Parse("."),
                            new MemoryStream(new Core.RawDns.RawDnsWriter()
                                .U16(decoded.Class)
                                .U32(decoded.Ttl)
                                .U16((UInt16) decoded.Rdata.Length)
                                .Bytes(decoded.Rdata)
                                .ToArray())
                        );

        Assert.That(DNSSECValidator.ComputeKeyTag(reparsed), Is.EqualTo((UInt16) 20326));

    }

    #endregion

    #region KeyTag_Of_A_Second_Published_Key()

    [Test]
    [Property("RFC", "4034 App. B")]
    public void KeyTag_Of_A_Second_Published_Key()
    {

        // The IANA root KSK-2024 (key tag 38696), published alongside KSK-2017
        // during the current rollover — a second independent check of the
        // Appendix B algorithm.
        var ksk2024 = new DNSKEY(
                          DomainName.Parse("."),
                          DNSQueryClasses.IN,
                          TimeSpan.FromDays(1),
                          257,
                          3,
                          8,
                          Convert.FromBase64String(
                              "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="
                          )
                      );

        Assert.That(DNSSECValidator.ComputeKeyTag(ksk2024), Is.EqualTo((UInt16) 38696));

    }

    #endregion

}
