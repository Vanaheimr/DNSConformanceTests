using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 5011 — automated updates of DNSSEC trust anchors.
///
/// The protocol is deliberately slow and suspicious: a newly published key must
/// be seen continuously for 30 days before it is trusted, and a revoked key must
/// never come back. Both properties exist so that a single compromised response
/// cannot install an attacker's key, so they are worth testing directly rather
/// than inferring from a successful rollover.
/// </summary>
[TestFixture]
[Property("RFC", "5011")]
public class TrustAnchorRolloverTests
{

    #region Helpers

    private const Byte  RsaSha256   = 8;
    private const UInt16 KskFlags   = 257;            // ZONE | SEP
    private const UInt16 ZskFlags   = 256;            // ZONE
    private const UInt16 RevokeBit  = 0x0080;

    private static DNSKEY RootKey(UInt16 Flags, Byte Seed)
    {

        // The bytes need not be a real key: nothing here verifies a signature, and
        // the key tag is a checksum over the RDATA either way.
        var publicKey = new Byte[64];
        Array.Fill(publicKey, Seed);

        return new DNSKEY(
                   DomainName.Parse("."),
                   DNSQueryClasses.IN,
                   TimeSpan.FromDays(1),
                   Flags,
                   3,
                   RsaSha256,
                   publicKey
               );

    }

    private static StubDnsClient RootServing(params DNSKEY[] Keys)
        => new StubDnsClient().Answer(".", DNSResourceRecordTypes.DNSKEY, Keys);

    #endregion


    #region Add_Hold_Down_Is_Thirty_Days()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public void Add_Hold_Down_Is_Thirty_Days()
    {

        Assert.That(DNSSECValidator.AddHoldDownTime, Is.EqualTo(TimeSpan.FromDays(30)),
                    "RFC 5011 fixes the add hold-down at 30 days");

    }

    #endregion

    #region New_Ksk_Enters_Hold_Down_Rather_Than_Becoming_An_Anchor()

    [Test]
    [Property("RFC", "5011 §2.3")]
    public async Task New_Ksk_Enters_Hold_Down_Rather_Than_Becoming_An_Anchor()
    {

        // Seeing a new KSK once means nothing. If a single probe could install a
        // trust anchor, anyone able to answer one query would own the resolver.
        var newKsk    = RootKey(KskFlags, 0x11);
        var validator = new DNSSECValidator(RootServing(newKsk));

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified,               Is.False, "nothing is trusted yet, so nothing changed");
            Assert.That(validator.TrustAnchors, Is.Empty, "the key must not become an anchor on first sight");

            Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1),
                        "…it must start its hold-down instead");

            Assert.That(validator.PendingAnchors.Keys.Single().KeyTag,
                        Is.EqualTo(DNSSECValidator.ComputeKeyTag(newKsk)));

        });

    }

    #endregion

    #region Repeated_Sightings_Do_Not_Shorten_The_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task Repeated_Sightings_Do_Not_Shorten_The_Hold_Down()
    {

        // The hold-down is wall-clock time, not a sighting count — otherwise an
        // attacker who can answer repeatedly could simply probe it away.
        var newKsk    = RootKey(KskFlags, 0x22);
        var validator = new DNSSECValidator(RootServing(newKsk));

        for (var i = 0; i < 5; i++)
            await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(validator.TrustAnchors,   Is.Empty);
            Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1));
        });

    }

    #endregion

    #region Pending_Key_That_Stops_Being_Published_Is_Dropped()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task Pending_Key_That_Stops_Being_Published_Is_Dropped()
    {

        // RFC 5011 requires the key to be present *continuously* through the
        // hold-down. A key that vanishes restarts from zero if it reappears.
        var newKsk    = RootKey(KskFlags, 0x33);
        var resolver  = RootServing(newKsk);
        var validator = new DNSSECValidator(resolver);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1), "hold-down started");

        // The zone stops publishing it.
        resolver.Answer(".", DNSResourceRecordTypes.DNSKEY, RootKey(ZskFlags, 0x44));

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.PendingAnchors, Is.Empty,
                    "a key that is no longer published must not keep accruing hold-down time");

    }

    #endregion

    #region Zone_Signing_Keys_Never_Enter_The_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.1")]
    public async Task Zone_Signing_Keys_Never_Enter_The_Hold_Down()
    {

        // Only Secure Entry Points are candidates. A ZSK is not one.
        var validator = new DNSSECValidator(RootServing(RootKey(ZskFlags, 0x55)));

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(validator.PendingAnchors, Is.Empty);
            Assert.That(validator.TrustAnchors,   Is.Empty);
        });

    }

    #endregion

    #region Unreachable_Root_Changes_Nothing()

    [Test]
    public async Task Unreachable_Root_Changes_Nothing()
    {

        var validator = new DNSSECValidator(new StubDnsClient { Unreachable = true });

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(modified,                 Is.False);
            Assert.That(validator.PendingAnchors, Is.Empty, "a failed probe must not start a hold-down");
        });

    }

    #endregion

    #region Revoked_Ksk_Is_Removed_From_The_Trust_Anchors()

    [Test]
    [Property("RFC", "5011 §2.1")]
    public async Task Revoked_Ksk_Is_Removed_From_The_Trust_Anchors()
    {

        // A resolver stores the anchor for a key while the REVOKE bit is clear.
        // When the key is later republished with REVOKE set, the resolver has to
        // recognize it as *that same key* and drop it.
        //
        // The catch is that the key tag is a checksum over the whole RDATA,
        // including the Flags field — so setting REVOKE changes it. Matching the
        // revoked key against the stored anchor by its new tag can never succeed,
        // and the revocation is silently ignored: exactly the case RFC 5011 §2.1
        // exists to handle.
        var key       = RootKey(KskFlags, 0x66);
        var revoked   = RootKey((UInt16) (KskFlags | RevokeBit), 0x66);

        var liveTag   = DNSSECValidator.ComputeKeyTag(key);

        Assert.That(DNSSECValidator.ComputeKeyTag(revoked), Is.Not.EqualTo(liveTag),
                    "setting REVOKE necessarily changes the key tag");

        var anchor    = new DS(
                            DomainName.Parse("."),
                            DNSQueryClasses.IN,
                            TimeSpan.FromDays(365),
                            liveTag,
                            RsaSha256,
                            2,
                            new Byte[32]
                        );

        var validator = new DNSSECValidator(RootServing(revoked), [anchor]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.TrustAnchors, Is.Empty,
                    "a revoked KSK must be removed from the trust anchors");

    }

    #endregion

    #region Revoked_Key_Cannot_Come_Back()

    [Test]
    [Property("RFC", "5011 §2.1")]
    public async Task Revoked_Key_Cannot_Come_Back()
    {

        // Revocation has to be permanent. If republishing the key with REVOKE
        // cleared started a fresh hold-down, an attacker holding a compromised key
        // would only need to wait 30 days to have it trusted again — and the
        // operator's revocation would have bought nothing.
        var key      = RootKey(KskFlags, 0x77);
        var revoked  = RootKey((UInt16) (KskFlags | RevokeBit), 0x77);

        var anchor   = new DS(
                           DomainName.Parse("."),
                           DNSQueryClasses.IN,
                           TimeSpan.FromDays(365),
                           DNSSECValidator.ComputeKeyTag(key),
                           RsaSha256,
                           2,
                           new Byte[32]
                       );

        var resolver  = RootServing(revoked);
        var validator = new DNSSECValidator(resolver, [anchor]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.TrustAnchors, Is.Empty, "revocation took effect");

        // The zone publishes the very same key again, REVOKE cleared.
        resolver.Answer(".", DNSResourceRecordTypes.DNSKEY, key);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(validator.PendingAnchors, Is.Empty, "a revoked key must not start a new hold-down");
            Assert.That(validator.TrustAnchors,   Is.Empty);
        });

    }

    #endregion

}
