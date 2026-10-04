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
///
/// <para>
/// Every root DNSKEY RRset here is signed for real, the way the root signs it. RFC
/// 5011 believes a set only once it is authenticated: a new key counts only when
/// "that RRSet is validated by an existing trust anchor" (§2), a revocation only
/// when the key is seen "in a self-signed RRSet" (§2.1). A test that feeds an
/// unsigned set is testing what a validator does with a forged answer, and these
/// tests are about what it does with a genuine one. The forged ones are at the
/// end of the file, under finding 71.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "5011")]
public class TrustAnchorRolloverTests
{

    #region Helpers

    private const Byte   EcdsaP256Sha256  = 13;
    private const Byte   RsaSha256        = 8;
    private const UInt16 RevokeBit        = 0x0080;

    private static readonly DomainName Root = DomainName.Parse(".");

    /// <summary>
    /// A key of the root, generated for the test: a KSK unless asked for a ZSK.
    /// </summary>
    private static DNSSECSigningKey RootKey(Boolean KeySigningKey = true)
        => DNSSECSigningKey.Generate(Root, EcdsaP256Sha256, KeySigningKey);

    /// <summary>
    /// The key as its owner publishes it to revoke it. Setting REVOKE changes the
    /// RDATA, and with it the key tag.
    /// </summary>
    private static DNSKEY Revoked(DNSSECSigningKey Key)
        => new (Root,
                DNSQueryClasses.IN,
                Key.DNSKEY.TimeToLive,
                (UInt16) (Key.DNSKEY.Flags | RevokeBit),
                Key.DNSKEY.Protocol,
                Key.DNSKEY.Algorithm,
                Key.DNSKEY.PublicKey);

    /// <summary>
    /// A signature over the root's DNSKEY RRset, valid from yesterday for sixty
    /// days — long enough to outlast the add hold-down, which some of the tests
    /// below travel through.
    /// </summary>
    private static RRSIG Sign(DNSKEY[] Keys, DNSSECSigningKey Key)
        => DNSSECZoneSigner.SignRRSet(Keys, Key, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(60));

    /// <summary>
    /// The signature a revoked key makes over the RRset it is revoked in: the same
    /// private key, and the key tag of the revoked form, which is the key that
    /// stands in the RRset (RFC 5011 §2.1, "self-signed").
    /// </summary>
    private static RRSIG SignRevoked(DNSKEY[] Keys, DNSSECSigningKey Key)
    {

        var live    = Sign(Keys, Key);
        var keyTag  = DNSSECValidator.ComputeKeyTag(Revoked(Key));

        RRSIG With(Byte[] Signature)
            => new (Root, DNSQueryClasses.IN, live.TimeToLive, live.TypeCovered, live.Algorithm, live.Labels,
                    live.OriginalTTL, live.SignatureExpiration, live.SignatureInception, keyTag, live.SignerName,
                    Signature);

        return With(Key.Sign(DNSSECCanonical.SignedData(Keys, With([]))));

    }

    /// <summary>
    /// The root's DNSKEY RRset, the keys and the signatures over them.
    /// </summary>
    private static StubDnsClient RootServing(DNSKEY[] Keys, params RRSIG[] Signatures)
        => new StubDnsClient().Answer(".", DNSResourceRecordTypes.DNSKEY, [.. Keys, .. Signatures]);

    /// <summary>
    /// The root's DNSKEY RRset with the keys given, signed by the anchor.
    /// </summary>
    private static StubDnsClient RootServing(DNSSECSigningKey Anchor, params DNSKEY[] Keys)
        => RootServing(Keys, Sign(Keys, Anchor));

    /// <summary>
    /// The anchor a resolver would have on file for this key: the DS of it, digest
    /// and all.
    /// </summary>
    private static DS AnchorFor(DNSSECSigningKey Key)
        => Key.DelegationSigner();

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
        // trust anchor, anyone able to answer one query would own the resolver —
        // and here the set is even genuinely signed by the anchor already trusted.
        using var anchor  = RootKey();
        using var newKsk  = RootKey();

        var validator = new DNSSECValidator(RootServing(anchor, anchor.DNSKEY, newKsk.DNSKEY), [AnchorFor(anchor)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified, Is.False, "nothing new is trusted yet, so nothing changed");

            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag), Is.EqualTo(new[] { anchor.KeyTag }),
                        "the key must not become an anchor on first sight");

            Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1),
                        "…it must start its hold-down instead");

            Assert.That(validator.PendingAnchors.Keys.Single().KeyTag,
                        Is.EqualTo(newKsk.KeyTag));

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
        using var known  = RootKey();

        var validator = new DNSSECValidator(RootServing(known, known.DNSKEY), [AnchorFor(known)]);

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
        // checksum: RFC 4034 Appendix B says so outright. A key of another algorithm is
        // another key however its checksum comes out, so an anchor that happens
        // to share its tag does not vouch for it, and it has to serve a hold-down
        // like any newcomer.
        using var anchor    = RootKey();
        using var incoming  = RootKey();

        var otherAlg  = new DS(
                            Root,
                            DNSQueryClasses.IN,
                            TimeSpan.FromDays(365),
                            incoming.KeyTag,
                            RsaSha256,                       // the newcomer is ECDSAP256SHA256
                            2,
                            new Byte[32]
                        );

        var validator = new DNSSECValidator(RootServing(anchor, anchor.DNSKEY, incoming.DNSKEY),
                                            [AnchorFor(anchor), otherAlg]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified,                 Is.False, "a new key is not trusted on the day it appears");
            Assert.That(validator.TrustAnchors,   Has.Count.EqualTo(2), "the anchor of the other algorithm is untouched");
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
        using var anchor  = RootKey();
        using var newKsk  = RootKey();

        var validator = new DNSSECValidator(RootServing(anchor, anchor.DNSKEY, newKsk.DNSKEY), [AnchorFor(anchor)]);

        for (var i = 0; i < 5; i++)
            await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(validator.TrustAnchors,   Has.Count.EqualTo(1), "still only the anchor it started with");
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
        using var existing  = RootKey();
        using var incoming  = RootKey();

        var validator = new DNSSECValidator(RootServing(existing, existing.DNSKEY, incoming.DNSKEY), [AnchorFor(existing)]);

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
                            Contains.Item(incoming.KeyTag));

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
        using var existing  = RootKey();
        using var incoming  = RootKey();

        var validator = new DNSSECValidator(RootServing(existing, existing.DNSKEY, incoming.DNSKEY), [AnchorFor(existing)]);

        var seen      = Timestamp.Now;

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(seen),
                    Is.False, "the first sighting starts the clock");

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(seen + DNSSECValidator.AddHoldDownTime - TimeSpan.FromSeconds(1)),
                    Is.False, "one second short of the hold-down is short of it");

        Assert.That(await validator.ProbeForTrustAnchorUpdatesAsync(seen + DNSSECValidator.AddHoldDownTime),
                    Is.True, "and the instant it runs out is inside it");

        Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                    Contains.Item(incoming.KeyTag));

    }

    #endregion

    #region Pending_Key_That_Stops_Being_Published_Is_Dropped()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    public async Task Pending_Key_That_Stops_Being_Published_Is_Dropped()
    {

        // RFC 5011 requires the key to be present *continuously* through the
        // hold-down. A key that vanishes restarts from zero if it reappears.
        using var anchor  = RootKey();
        using var newKsk  = RootKey();
        using var zsk     = RootKey(KeySigningKey: false);

        var resolver  = RootServing(anchor, anchor.DNSKEY, newKsk.DNSKEY);
        var validator = new DNSSECValidator(resolver, [AnchorFor(anchor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.PendingAnchors, Has.Count.EqualTo(1), "hold-down started");

        // The zone stops publishing it, in a set as genuinely signed as the first.
        DNSKEY[] without = [anchor.DNSKEY, zsk.DNSKEY];

        resolver.Answer(".", DNSResourceRecordTypes.DNSKEY, [.. without, Sign(without, anchor)]);

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
        using var anchor  = RootKey();
        using var zsk     = RootKey(KeySigningKey: false);

        var validator = new DNSSECValidator(RootServing(anchor, anchor.DNSKEY, zsk.DNSKEY), [AnchorFor(anchor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(validator.PendingAnchors, Is.Empty);
            Assert.That(validator.TrustAnchors,   Has.Count.EqualTo(1), "still only the anchor it started with");
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
        using var known  = RootKey();

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
        //
        // The set is the one the root published when it revoked KSK-2010: the
        // successor, already an anchor, signs it, and so does the revoked key.
        using var key        = RootKey();
        using var successor  = RootKey();

        var revoked   = Revoked(key);

        Assert.That(DNSSECValidator.ComputeKeyTag(revoked), Is.Not.EqualTo(key.KeyTag),
                    "setting REVOKE necessarily changes the key tag");

        DNSKEY[] keys = [revoked, successor.DNSKEY];

        var validator = new DNSSECValidator(RootServing(keys, Sign(keys, successor), SignRevoked(keys, key)),
                                            [AnchorFor(key), AnchorFor(successor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.TrustAnchors.Select(a => a.KeyTag), Is.EqualTo(new[] { successor.KeyTag }),
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
        using var doomed     = RootKey();
        using var bystander  = RootKey();               // same algorithm, another key

        Assert.That(bystander.KeyTag, Is.Not.EqualTo(doomed.KeyTag),
                    "the two keys are distinct, which is what the test is about");

        DNSKEY[] keys  = [Revoked(doomed), bystander.DNSKEY];

        var validator  = new DNSSECValidator(RootServing(keys, Sign(keys, bystander), SignRevoked(keys, doomed)),
                                             [AnchorFor(doomed), AnchorFor(bystander)]);

        var modified   = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {

            Assert.That(modified, Is.True, "an anchor was removed, so the set changed");

            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                        Does.Not.Contain(doomed.KeyTag),
                        "the revoked key is gone");

            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                        Contains.Item(bystander.KeyTag),
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
        using var known     = RootKey();
        using var stranger  = RootKey();

        DNSKEY[] keys = [known.DNSKEY, Revoked(stranger)];

        var validator = new DNSSECValidator(RootServing(keys, Sign(keys, known), SignRevoked(keys, stranger)),
                                            [AnchorFor(known)]);

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
        using var key        = RootKey();
        using var successor  = RootKey();

        DNSKEY[] revoking   = [Revoked(key), successor.DNSKEY];

        var resolver  = RootServing(revoking, Sign(revoking, successor), SignRevoked(revoking, key));
        var validator = new DNSSECValidator(resolver, [AnchorFor(key), AnchorFor(successor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.TrustAnchors.Select(a => a.KeyTag), Is.EqualTo(new[] { successor.KeyTag }),
                    "revocation took effect");

        // The zone publishes the very same key again, REVOKE cleared, in a set
        // the remaining anchor signs.
        DNSKEY[] returning  = [key.DNSKEY, successor.DNSKEY];

        resolver.Answer(".", DNSResourceRecordTypes.DNSKEY, [.. returning, Sign(returning, successor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(validator.PendingAnchors, Is.Empty, "a revoked key must not start a new hold-down");
            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag), Is.EqualTo(new[] { successor.KeyTag }));
        });

    }

    #endregion


    // Finding 71. Everything above feeds the probe a set the root would sign.
    // Everything below feeds it one the root did not, and asks that it change
    // nothing: the hold-down exists so that an answer cannot install a key, and
    // the REVOKE bit needs the revoked key's own signature so that an answer
    // cannot remove one.

    #region (private static) Forged(Signature)

    /// <summary>
    /// The signature an attacker without the private key can produce: every field
    /// the genuine one has, key tag included, and zeros where the signature goes.
    /// </summary>
    private static RRSIG Forged(RRSIG Genuine)
        => new (Root, DNSQueryClasses.IN, Genuine.TimeToLive, Genuine.TypeCovered, Genuine.Algorithm, Genuine.Labels,
                Genuine.OriginalTTL, Genuine.SignatureExpiration, Genuine.SignatureInception, Genuine.KeyTag, Genuine.SignerName,
                new Byte[Genuine.Signature.Length]);

    #endregion

    #region An_Unsigned_Key_Set_Starts_No_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.2")]
    [Category(TestCategories.KnownIssue)]
    public async Task An_Unsigned_Key_Set_Starts_No_Hold_Down()
    {

        // The attack in its plainest form: the anchor's key, the attacker's key
        // beside it, and no signature at all. Answered for thirty days, it made
        // the attacker's key an anchor.
        using var anchor    = RootKey();
        using var attacker  = RootKey();

        var validator = new DNSSECValidator(RootServing([anchor.DNSKEY, attacker.DNSKEY]), [AnchorFor(anchor)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(modified,                 Is.False);
            Assert.That(validator.PendingAnchors, Is.Empty, "a set nobody signed vouches for no key in it");
        });

    }

    #endregion

    #region A_Forged_Signature_Starts_No_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.2")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Forged_Signature_Starts_No_Hold_Down()
    {

        // An RRSIG that names the anchor's key by tag, algorithm and signer, and
        // does not verify. Finding one is not the same as checking it.
        using var anchor    = RootKey();
        using var attacker  = RootKey();

        DNSKEY[] keys = [anchor.DNSKEY, attacker.DNSKEY];

        var validator = new DNSSECValidator(RootServing(keys, Forged(Sign(keys, anchor))), [AnchorFor(anchor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.PendingAnchors, Is.Empty);

    }

    #endregion

    #region A_Set_Signed_Only_By_The_Newcomer_Starts_No_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.2")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Set_Signed_Only_By_The_Newcomer_Starts_No_Hold_Down()
    {

        // A genuine signature by the key that wants to be trusted proves only
        // that whoever published it holds its private key — which the attacker
        // does. §2.2 asks for the signature of a key already trusted.
        using var anchor    = RootKey();
        using var attacker  = RootKey();

        DNSKEY[] keys = [anchor.DNSKEY, attacker.DNSKEY];

        var validator = new DNSSECValidator(RootServing(attacker, keys), [AnchorFor(anchor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.PendingAnchors, Is.Empty);

    }

    #endregion

    #region An_Unauthenticated_Set_Does_Not_Interrupt_A_Hold_Down()

    [Test]
    [Property("RFC", "5011 §2.4.1")]
    [Category(TestCategories.KnownIssue)]
    public async Task An_Unauthenticated_Set_Does_Not_Interrupt_A_Hold_Down()
    {

        // The continuity rule read from the other side. A key that the root stops
        // publishing loses its hold-down — but only the root can say that it
        // stopped. A forged answer that leaves the key out would otherwise reset
        // every rollover in progress, once a month, for good.
        using var anchor    = RootKey();
        using var incoming  = RootKey();

        var resolver  = RootServing(anchor, anchor.DNSKEY, incoming.DNSKEY);
        var validator = new DNSSECValidator(resolver, [AnchorFor(anchor)]);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        resolver.Answer(".", DNSResourceRecordTypes.DNSKEY, anchor.DNSKEY);

        await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.That(validator.PendingAnchors.Keys.Select(id => id.KeyTag), Is.EqualTo(new[] { incoming.KeyTag }),
                    "the newcomer's hold-down is still running");

    }

    #endregion

    #region A_Revocation_In_An_Unsigned_Set_Is_Ignored()

    [Test]
    [Property("RFC", "5011 §2.1")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Revocation_In_An_Unsigned_Set_Is_Ignored()
    {

        // One forged answer, the anchor's own public key with the REVOKE bit set,
        // and the resolver was left without its trust anchor.
        using var anchor = RootKey();

        var validator = new DNSSECValidator(RootServing([Revoked(anchor)]), [AnchorFor(anchor)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(modified, Is.False);
            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag), Is.EqualTo(new[] { anchor.KeyTag }));
        });

    }

    #endregion

    #region A_Revocation_The_Revoked_Key_Did_Not_Sign_Is_Ignored()

    [Test]
    [Property("RFC", "5011 §2.1")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Revocation_The_Revoked_Key_Did_Not_Sign_Is_Ignored()
    {

        // What the REVOKE bit was designed against, in RFC 5011's own words:
        // "Assume that B has been compromised. Without a specific revocation bit,
        // B could invalidate A". The set here is genuinely signed by an anchor —
        // the compromised one — and still says nothing about the other's
        // revocation unless that key signed it too.
        using var victim       = RootKey();
        using var compromised  = RootKey();

        DNSKEY[] keys = [Revoked(victim), compromised.DNSKEY];

        var validator = new DNSSECValidator(RootServing(keys, Sign(keys, compromised)),
                                            [AnchorFor(victim), AnchorFor(compromised)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(modified, Is.False);
            Assert.That(validator.TrustAnchors.Select(a => a.KeyTag),
                        Is.EquivalentTo(new[] { victim.KeyTag, compromised.KeyTag }));
        });

    }

    #endregion

    #region A_Revocation_Removes_No_Anchor_That_Merely_Shares_Its_Tag()

    [Test]
    [Property("RFC", "5011 §2.1")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Revocation_Removes_No_Anchor_That_Merely_Shares_Its_Tag()
    {

        // The self-signature proves who revoked the key; it is the anchor that
        // names the key which decides what the revocation removes. A key tag is a
        // sixteen-bit checksum — RFC 4034 Appendix B: "not a unique identifier" — and a
        // key of one's own with any tag one likes is a few seconds of trying. So
        // a stranger's genuine, self-signed revocation removes no anchor whose tag
        // and algorithm it happens to share: it is not that anchor's key.
        using var anchor    = RootKey();
        using var stranger  = RootKey();

        var namesake  = new DS(
                            Root,
                            DNSQueryClasses.IN,
                            TimeSpan.FromDays(365),
                            stranger.KeyTag,                 // the tag the stranger had before revoking
                            EcdsaP256Sha256,
                            2,
                            new Byte[32]                     // and the digest of some other key
                        );

        DNSKEY[] keys = [anchor.DNSKEY, Revoked(stranger)];

        var validator = new DNSSECValidator(RootServing(keys, Sign(keys, anchor), SignRevoked(keys, stranger)),
                                            [AnchorFor(anchor), namesake]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(modified,               Is.False, "the stranger's key was never an anchor here");
            Assert.That(validator.TrustAnchors, Has.Count.EqualTo(2));
        });

    }

    #endregion

    #region A_Self_Signed_Revocation_Vouches_For_Nothing_Else()

    [Test]
    [Property("RFC", "5011 §2.1")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Self_Signed_Revocation_Vouches_For_Nothing_Else()
    {

        // §2.1 makes a revocation valid on the revoked key's own signature — "Unlike
        // the 'Add' operation below, revocation is immediate" — so it takes effect
        // even where no other anchor signed the set. But it limits what that
        // signature may be used for: nothing "except to validate the RRSIG it
        // signed over the DNSKEY RRSet specifically for the purpose of validating
        // the revocation". The newcomer beside it starts no hold-down on its word.
        using var anchor    = RootKey();
        using var incoming  = RootKey();

        DNSKEY[] keys = [Revoked(anchor), incoming.DNSKEY];

        var validator = new DNSSECValidator(RootServing(keys, SignRevoked(keys, anchor)), [AnchorFor(anchor)]);

        var modified  = await validator.ProbeForTrustAnchorUpdatesAsync();

        Assert.Multiple(() => {
            Assert.That(modified,                 Is.True, "the revocation took effect");
            Assert.That(validator.TrustAnchors,   Is.Empty);
            Assert.That(validator.PendingAnchors, Is.Empty, "and nothing else in the set did");
        });

    }

    #endregion

}
