using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Illias;

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

    /// <summary>
    /// The anchor a resolver would have on file for this key. The probe finds an
    /// anchor by key tag and algorithm and never looks at the digest, so the
    /// digest is left at zero rather than computed.
    /// </summary>
    private static DS AnchorFor(DNSKEY Key)
        => new (DomainName.Parse("."),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(365),
                DNSSECValidator.ComputeKeyTag(Key),
                Key.Algorithm,
                2,
                new Byte[32]);

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

    #region A_Key_Already_Trusted_Starts_No_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task A_Key_Already_Trusted_Starts_No_Hold_Down()
    {

        // The hold-down is for keys the resolver does not yet trust. A key it
        // already has an anchor for is recognised as one and starts no timer —
        // and the timer is the only place that recognition shows. A resolver that
        // failed to recognise the key would report no change today as well, and
        // differ only a month later, by adding an anchor it already had.
        var known     = RootKey(KskFlags, 0xCC);
        var validator = new DNSSECValidator(RootServing(known), [AnchorFor(known)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified,                 Is.False, "the key is already trusted; there is nothing to decide");
            Assert.That(validator.TrustAnchors,   Has.Count.EqualTo(1), "and it is not added a second time");
            Assert.That(validator.PendingAnchors, Is.Empty, "nor put on a hold-down it has no need of");

        });

    }

    #endregion

    #region A_Key_Sharing_A_Tag_With_An_Anchor_Is_Still_New()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task A_Key_Sharing_A_Tag_With_An_Anchor_Is_Still_New()
    {

        // The recognition is by tag *and* algorithm, because the tag alone is a
        // checksum: RFC 4034 §5.1 says so outright. A key of another algorithm is
        // another key however its checksum comes out, so an anchor that happens
        // to share its tag does not vouch for it, and it has to serve a hold-down
        // like any newcomer.
        var incoming  = RootKey(KskFlags, 0xDD);

        var otherAlg  = new DS(
                            DomainName.Parse("."),
                            DNSQueryClasses.IN,
                            TimeSpan.FromDays(365),
                            DNSSECValidator.ComputeKeyTag(incoming),
                            (Byte) (RsaSha256 + 5),          // ECDSAP256SHA256
                            2,
                            new Byte[32]
                        );

        var validator = new DNSSECValidator(RootServing(incoming), [otherAlg]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified,                 Is.False, "a new key is not trusted on the day it appears");
            Assert.That(validator.TrustAnchors,   Has.Count.EqualTo(1), "the anchor of the other algorithm is untouched");
            Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1), "and the newcomer is on hold-down, not mistaken for it");

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

    #region A_Key_Is_Admitted_Once_Its_Hold_Down_Has_Run()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task A_Key_Is_Admitted_Once_Its_Hold_Down_Has_Run()
    {

        // The other end of the hold-down: having waited it out, the key is
        // admitted — and the caller is told so, which is what has it write the
        // new trust store out. A rollover that completes silently is undone by
        // the next restart.
        var existing  = RootKey(KskFlags, 0xEE);
        var incoming  = RootKey(KskFlags, 0xE1);

        var validator = new DNSSECValidator(RootServing(existing, incoming), [AnchorFor(existing)]);

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(), Is.False,
                    "the first sighting starts the clock and nothing more");

        Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1),
                    "the newcomer, and only the newcomer, is waiting");

        Timestamp.TravelForwardInTime(DNSSECValidator.AddHoldDownTime + TimeSpan.FromHours(1));

        try
        {

            var modified = await validator.ProbeForTrustAnchorUpdatesAsync();

            Assert.Multiple(() => {

                Assert.That(modified, Is.True,
                            "a month of continuous presence later it is admitted, and said to be");

                Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                            Contains.Item(DNSSECValidator.ComputeKeyTag(incoming)));

                Assert.That(validator.PendingAnchors, Is.Empty,
                            "and it is no longer waiting for anything");

            });

        }
        finally
        {
            Timestamp.Reset();
        }

    }

    #endregion

    #region The_Hold_Down_Includes_The_Instant_It_Runs_Out()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task The_Hold_Down_Includes_The_Instant_It_Runs_Out()
    {

        // §2.4.1 admits a key that has been continuously present "for the
        // duration of the add hold-down time" — the instant the interval closes
        // belongs to it, and a second either side of that instant is the whole
        // difference between >= and >.
        //
        // It cannot be named by moving the clock. FirstSeen is read at one probe
        // and compared at the next, so the difference carries the real time the
        // two probes took however far the clock travelled in between, and the two
        // readings can never be made to differ by exactly thirty days. Saying what
        // "now" is, is the only way to stand on the boundary — and no clock is
        // moved here, so the test leaves nothing behind for the next one.
        var existing  = RootKey(KskFlags, 0xB1);
        var incoming  = RootKey(KskFlags, 0xB2);

        var validator = new DNSSECValidator(RootServing(existing, incoming), [AnchorFor(existing)]);

        var seen      = Timestamp.Now;

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(seen),
                    Is.False, "the first sighting starts the clock");

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(seen + DNSSECValidator.AddHoldDownTime - TimeSpan.FromSeconds(1)),
                    Is.False, "one second short of the hold-down is short of it");

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(seen + DNSSECValidator.AddHoldDownTime),
                    Is.True, "and the instant it runs out is inside it");

        Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                    Contains.Item(DNSSECValidator.ComputeKeyTag(incoming)));

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

    #region A_Probe_Whose_Transport_Fails_Changes_Nothing()

    [Test]
    public async Task A_Probe_Whose_Transport_Fails_Changes_Nothing()
    {

        // The case above is a resolver that answered "I do not know". This is the
        // one where nothing answers at all and the query throws. Both have to come
        // back as no change: a caller persists its trust store when the answer is
        // yes, and a probe that learned nothing has nothing to persist.
        var known     = RootKey(KskFlags, 0xF1);

        var validator = new DNSSECValidator(new StubDnsClient { Throws = true },
                                            [AnchorFor(known)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified,                 Is.False, "nothing was learned, so nothing changed");
            Assert.That(validator.TrustAnchors,   Has.Count.EqualTo(1), "and a failed probe revokes nothing");
            Assert.That(validator.PendingAnchors, Is.Empty);

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

    #region A_Revocation_Removes_Only_The_Revoked_Key()

    [Test]
    [Property("RFC", "5011 §2.1")]
    public async Task A_Revocation_Removes_Only_The_Revoked_Key()
    {

        // The removal matches an anchor on tag and algorithm. Dropping every
        // anchor that merely shares the algorithm would empty most of a trust
        // store on one compromised key — so the bystander is the assertion that
        // matters here, and the caller being told the set changed is the other.
        var doomed     = RootKey(KskFlags, 0x88);
        var bystander  = RootKey(KskFlags, 0x89);      // same algorithm, another key
        var revoked    = RootKey((UInt16) (KskFlags | RevokeBit), 0x88);

        Assert.That(DNSSECValidator.ComputeKeyTag(bystander),
                    Is.Not.EqualTo(DNSSECValidator.ComputeKeyTag(doomed)),
                    "the two keys are distinct, which is what the test is about");

        var validator  = new DNSSECValidator(RootServing(revoked, bystander),
                                             [AnchorFor(doomed), AnchorFor(bystander)]);

        var modified   = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified, Is.True, "an anchor was removed, so the set changed");

            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                        Does.Not.Contain(DNSSECValidator.ComputeKeyTag(doomed)),
                        "the revoked key is gone");

            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                        Contains.Item(DNSSECValidator.ComputeKeyTag(bystander)),
                        "and the one that was not revoked is still there");

        });

    }

    #endregion

    #region Revoking_A_Key_That_Was_Never_An_Anchor_Reports_No_Change()

    [Test]
    [Property("RFC", "5011 §2.1")]
    public async Task Revoking_A_Key_That_Was_Never_An_Anchor_Reports_No_Change()
    {

        // A revocation for a key this resolver never trusted removes nothing, so
        // nothing changed. Reporting a change would have the caller write out a
        // trust store identical to the one it has — harmless once, and a lie
        // about what happened.
        var known     = RootKey(KskFlags, 0xAA);
        var stranger  = RootKey((UInt16) (KskFlags | RevokeBit), 0xBB);

        var validator = new DNSSECValidator(RootServing(stranger), [AnchorFor(known)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified,               Is.False, "nothing was removed, so nothing was modified");
            Assert.That(validator.TrustAnchors, Has.Count.EqualTo(1));

        });

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
