using System.Buffers.Binary;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 8945 §5.1 and RFC 2931 §3.2 — what the two strip functions say about a
/// message, before anything asks whether its signature is any good.
///
/// <para>
/// Both are the front door: <c>TryStripTSIG</c> and <c>TryStripSIG0</c> run on
/// whatever a peer sent, before a key is chosen and before a MAC is computed, and
/// every verification path in the stack begins by calling one of them. A strip
/// that answered "yes, signed" for a message that is not is how an unauthenticated
/// message gets as far as code that assumes it was checked.
/// </para>
///
/// <para>
/// The messages here are built with the suite's own writer and handed over as
/// octets, because that is the only form the real thing ever arrives in.
/// </para>
/// </summary>
[TestFixture]
public class TransactionSignatureStrippingTests
{

    #region Data

    private static readonly Byte[]     Secret      = Convert.FromBase64String("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=");
    private static readonly DomainName SignerName  = DomainName.Parse("signer.conformance.test");

    private const Byte AlgorithmRSASHA256 = 8;

    private static TSIGKey Key()
        => new (DomainName.Parse("test-key."), Secret);

    private static Byte[] Query()
        => RawDnsWriter.Query(0x8945, "example.", RawDnsType.A);

    /// <summary>A query carrying an OPT as its last additional record, and nothing else.</summary>
    private static Byte[] QueryWithOpt()
        => RawDnsWriter.Query(0x8945, "example.", RawDnsType.A, ednsPayloadSize: 1232);

    /// <summary>A bare header: twelve octets, every count zero (RFC 1035 §4.1.1).</summary>
    private static Byte[] BareHeader()
        => new RawDnsWriter().Header(0x8945, 0, 0, 0, 0, 0).ToArray();

    #endregion


    // ------------------------------------------------ what is not a signature

    #region An_Unsigned_Message_Is_Not_Stripped()

    /// <summary>
    /// The plain cases, each for its own reason. A message with no additional
    /// records has nothing at the end to be a signature; one whose last record is
    /// an OPT has something there that is not one.
    /// </summary>
    [Test]
    [Property("RFC", "8945 §5.1")]
    public void An_Unsigned_Message_Is_Not_Stripped()
    {

        Assert.Multiple(() => {

            Assert.That(TSIGSigner.TryStripTSIG(Query(), out _, out _), Is.False,
                        "a query with no additional records carries no TSIG");

            Assert.That(SIG0Signer.TryStripSIG0(Query(), out _, out _), Is.False,
                        "…and no SIG(0) either");

            Assert.That(TSIGSigner.TryStripTSIG(QueryWithOpt(), out _, out _), Is.False,
                        "an OPT is the last record here, and an OPT is not a TSIG");

            Assert.That(SIG0Signer.TryStripSIG0(QueryWithOpt(), out _, out _), Is.False,
                        "…nor a SIG");

        });

    }

    #endregion

    #region A_Message_Too_Short_To_Have_A_Header_Is_Not_Stripped()

    /// <summary>
    /// RFC 1035 §4.1.1's header is twelve octets. Anything shorter is not a
    /// message at all, and the strip functions are handed octets from the network
    /// — so answering rather than reading past the end is the whole job.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void A_Message_Too_Short_To_Have_A_Header_Is_Not_Stripped()
    {

        Assert.Multiple(() => {

            foreach (var length in new[] { 0, 1, 11 })
            {

                var runt = new Byte[length];

                Assert.That(TSIGSigner.TryStripTSIG(runt, out _, out _), Is.False,
                            $"{length} octets is not a DNS message");

                Assert.That(SIG0Signer.TryStripSIG0(runt, out _, out _), Is.False,
                            $"{length} octets is not a DNS message");

            }

            Assert.That(TSIGSigner.TryStripTSIG(BareHeader(), out _, out _), Is.False,
                        "and a header with no records is a message, just not a signed one");

            Assert.That(SIG0Signer.TryStripSIG0(BareHeader(), out _, out _), Is.False);

        });

    }

    #endregion

    #region A_Message_Whose_Arcount_Lies_Is_Not_Stripped()

    /// <summary>
    /// ARCOUNT says how many additional records follow. A message claiming one
    /// and carrying none cannot have a signature at its end, and the walk that
    /// would look for it runs off the message instead — which is the shape a
    /// hostile sender reaches for.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void A_Message_Whose_Arcount_Lies_Is_Not_Stripped()
    {

        var lying = new RawDnsWriter().Header(0x8945, 0, 0, 0, 0, 1).ToArray();

        Assert.Multiple(() => {

            Assert.That(lying, Has.Length.EqualTo(12),
                        "twelve octets, and a header promising a record that is not there");

            Assert.That(TSIGSigner.TryStripTSIG(lying, out _, out _), Is.False);
            Assert.That(SIG0Signer.TryStripSIG0(lying, out _, out _), Is.False);

        });

    }

    #endregion

    #region A_Message_Cut_Off_Inside_Its_Last_Record_Is_Not_Stripped()

    /// <summary>
    /// A truncated record is the case where a reader either says no or walks past
    /// the end of the buffer. Here the TSIG is real and then the last octets of
    /// it are taken away.
    /// </summary>
    [Test]
    [Property("RFC", "8945 §5.1")]
    public void A_Message_Cut_Off_Inside_Its_Last_Record_Is_Not_Stripped()
    {

        using var rsa = RSA.Create(2048);

        var key       = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);

        var signed    = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);
        var sig0      = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256,
                                        data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                                        key.KeyTag);

        Assert.Multiple(() => {

            Assert.That(TSIGSigner.TryStripTSIG(signed, out _, out _), Is.True,
                        "the whole message is a signed one");

            Assert.That(TSIGSigner.TryStripTSIG(signed[..^8], out _, out _), Is.False,
                        "…and eight octets short of it is not");

            Assert.That(SIG0Signer.TryStripSIG0(sig0, out _, out _), Is.True);

            Assert.That(SIG0Signer.TryStripSIG0(sig0[..^8], out _, out _), Is.False,
                        "the same for a SIG(0), which has its own copy of this walk");

            // The other way a walk can end badly: the records are all whole and
            // then there are octets after them. Nothing in the message is short,
            // so the walk finishes — it just does not finish where the message
            // does, and a message with something after its last record is not a
            // message with a signature at the end.
            Assert.That(TSIGSigner.TryStripTSIG([.. signed, 0, 0, 0], out _, out _), Is.False,
                        "trailing octets mean the last record is not last");

            Assert.That(SIG0Signer.TryStripSIG0([.. sig0, 0, 0, 0], out _, out _), Is.False);

        });

    }

    #endregion


    // ---------------------------------------------- what a SIG(0) has to cover

    #region A_Sig_Over_An_Rrset_Is_Not_A_Transaction_Signature()

    /// <summary>
    /// RFC 2931 §3: a SIG(0) is a SIG whose Type Covered is zero. A SIG record
    /// covering an RRset can sit at the end of a message for its own reasons, and
    /// reading it as a transaction signature would mean checking a signature that
    /// was never made over this message.
    /// </summary>
    [Test]
    [Property("RFC", "2931 §3")]
    public void A_Sig_Over_An_Rrset_Is_Not_A_Transaction_Signature()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256,
                                     data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                                     key.KeyTag);

        // Turn the Type Covered field from 0 into A. The record is still a SIG and
        // still the last one; it now covers an RRset instead of this message, and
        // "type covered = 0" is the only thing that ever distinguished the two
        // uses of TYPE 24.
        var overAnRrset = signed.ToArray();
        var record      = RawDnsReader.Parse(overAnRrset).Additionals[^1];

        BinaryPrimitives.WriteUInt16BigEndian(overAnRrset.AsSpan(record.RdataOffset, 2), RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(SIG0Signer.IsSIG0Signed(signed), Is.True,
                        "a transaction signature is what Sign produces");

            Assert.That(SIG0Signer.IsSIG0Signed(overAnRrset), Is.False,
                        "the same record covering an RRset is not a transaction signature, " +
                        "and reading it as one would check a signature never made over this message");

            Assert.That(SIG0Signer.TryStripSIG0(overAnRrset, out _, out _), Is.True,
                        "it is still a SIG at the end — the strip finds it and the caller decides");

            Assert.That(SIG0Signer.IsSIG0Signed(Query()), Is.False,
                        "and an unsigned message is not one");

            Assert.That(SIG0Signer.IsSIG0Signed(QueryWithOpt()), Is.False,
                        "…nor is a message whose last record is an OPT");

        });

    }

    #endregion


    // ------------------------------------- one signature, and not two kinds

    #region A_Message_Carrying_Both_Kinds_Of_Signature_Is_Refused()

    /// <summary>
    /// RFC 2931 §3.2: "Requests and responses can either have a single TSIG or
    /// one SIG(0) but not both a TSIG and a SIG(0)."
    ///
    /// Both are last-record meta-RRs, so the only way to have both is to append
    /// one after the other. A verifier that checks the outermost and serves the
    /// request anyway would let a sender attach a valid signature of the kind
    /// that is checked and a decorative one of the kind that is not.
    /// </summary>
    [Test]
    [Property("RFC", "2931 §3.2")]
    public void A_Message_Carrying_Both_Kinds_Of_Signature_Is_Refused()
    {

        using var rsa = RSA.Create(2048);

        var key           = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);

        var tsigOnly      = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);

        var sig0Only      = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256,
                                            data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                                            key.KeyTag);

        // A TSIG first, then a SIG(0) over the whole thing.
        var sig0OverTsig  = SIG0Signer.Sign(tsigOnly, SignerName, AlgorithmRSASHA256,
                                            data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                                            key.KeyTag);

        // …and the other order.
        var tsigOverSig0  = TSIGSigner.Sign(sig0Only, Key(), TimeSigned: 1_700_000_000);

        Assert.Multiple(() => {

            Assert.That(SIG0Signer.CarriesBothTSIGAndSIG0(sig0OverTsig), Is.True,
                        "a SIG(0) appended behind a TSIG is both");

            Assert.That(SIG0Signer.CarriesBothTSIGAndSIG0(tsigOverSig0), Is.True,
                        "and so is a TSIG appended behind a SIG(0)");

            Assert.That(SIG0Signer.CarriesBothTSIGAndSIG0(tsigOnly),  Is.False,
                        "one TSIG is one signature");

            Assert.That(SIG0Signer.CarriesBothTSIGAndSIG0(sig0Only),  Is.False,
                        "and one SIG(0) is one signature");

            Assert.That(SIG0Signer.CarriesBothTSIGAndSIG0(Query()),   Is.False,
                        "and none is none");

        });

    }

    #endregion


    // --------------------------------------------- what can be signed at all

    #region A_Bare_Header_Can_Be_Signed()

    /// <summary>
    /// A message of twelve octets with every count zero is a whole, legal DNS
    /// message — RFC 1035 §4.1.1 requires the header and nothing after it. It is
    /// the shortest thing a peer can send, so it is also the shortest thing a
    /// signer has to be able to authenticate; refusing it would leave the empty
    /// message as the one a peer could send unsigned without anyone minding.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void A_Bare_Header_Can_Be_Signed()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var header = BareHeader();

        var tsig   = TSIGSigner.Sign(header, Key(), TimeSigned: 1_700_000_000);

        var sig0   = SIG0Signer.Sign(header, SignerName, AlgorithmRSASHA256,
                                     data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                                     key.KeyTag,
                                     Inception:  DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
                                     Expiration: DateTimeOffset.FromUnixTimeSeconds(1_700_003_600));

        Assert.Multiple(() => {

            Assert.That(TSIGSigner.Verify(tsig, Key(), Now: 1_700_000_000).IsValid, Is.True,
                        "a signed bare header verifies");

            Assert.That(SIG0Signer.Verify(sig0, key, DateTimeOffset.FromUnixTimeSeconds(1_700_001_000)).IsValid,
                        Is.True);

        });

    }

    #endregion

}
