using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 8945 — transaction signatures.
///
/// <para>
/// TSIG is not DNSSEC: it authenticates a single message between two parties
/// that already share a secret, where DNSSEC authenticates zone data for
/// everyone. It lives in this project because this is where the suite keeps
/// message-level cryptography, not because the two are related. If TSIG grows a
/// TKEY exchange and server integration, it has earned its own project.
/// </para>
///
/// <para>
/// Structural claims are checked with <c>RawDns</c> rather than by asking Hermod
/// to read back what Hermod wrote. The MAC values are checked against HMAC
/// applied to the digest input assembled by hand from §4.3.3, so a mistake in
/// Hermod's assembly order cannot agree with itself.
/// </para>
/// </summary>
[TestFixture]
public class TsigSigningTests
{

    private static readonly Byte[] Secret = Convert.FromBase64String("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=");

    private static TSIGKey Key(String Name = "test-key.")
        => new (DomainName.Parse(Name), Secret);

    private static Byte[] Query()
        => RawDnsWriter.Query(0x4711, "example.", RawDnsType.A);


    #region Signed_Message_Verifies_Under_The_Same_Key()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public void Signed_Message_Verifies_Under_The_Same_Key()
    {

        var signed  = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);
        var result  = TSIGSigner.Verify(signed, Key(), Now: 1_700_000_000);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.True, result.Description);
            Assert.That(result.Error,   Is.Zero);
            Assert.That(result.MAC,     Is.Not.Null.And.Length.EqualTo(32), "HMAC-SHA256 produces 32 octets");
        });

    }

    #endregion

    #region Tsig_Record_Is_Last_With_Class_ANY_And_Ttl_Zero()

    [Test]
    [Property("RFC", "8945 §4.2")]
    public void Tsig_Record_Is_Last_With_Class_ANY_And_Ttl_Zero()
    {

        var signed   = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);

        // Read back with the independent parser: if Hermod laid the record out
        // wrongly, asking Hermod would agree with the mistake.
        var message  = RawDnsReader.Parse(signed);
        var tsig     = message.Additionals[^1];

        Assert.Multiple(() => {

            Assert.That(tsig.Type,                 Is.EqualTo((UInt16) 250), "TSIG is TYPE 250");
            Assert.That(tsig.Class,                Is.EqualTo((UInt16) 255), "§4.2: CLASS is ANY");
            Assert.That(tsig.Ttl,                  Is.Zero,                  "§4.2: TTL is 0 — a TSIG is never cached");
            Assert.That(message.ConsumedBytes,     Is.EqualTo(signed.Length), "no trailing bytes after the TSIG");
            Assert.That(message.Additionals,       Has.Count.EqualTo(1),      "the query carried no OPT, so TSIG is the only additional");

        });

    }

    #endregion

    #region Signing_Increments_Arcount()

    [Test]
    [Property("RFC", "8945 §5.1")]
    public void Signing_Increments_Arcount()
    {

        var unsigned  = Query();
        var signed    = TSIGSigner.Sign(unsigned, Key(), TimeSigned: 1_700_000_000);

        Assert.Multiple(() => {
            Assert.That(RawDnsReader.Parse(unsigned).Additionals, Is.Empty);
            Assert.That(RawDnsReader.Parse(signed).  Additionals, Has.Count.EqualTo(1),
                        "ARCOUNT counts the TSIG even though the MAC does not cover it");
        });

    }

    #endregion

    #region Mac_Matches_The_Digest_Input_Of_Section_4_3_3()

    [Test]
    [Property("RFC", "8945 §4.3.3")]
    public void Mac_Matches_The_Digest_Input_Of_Section_4_3_3()
    {

        // The digest input, assembled here straight from the specification:
        // the message, then the TSIG variables in a fixed order. If Hermod
        // orders or sizes any field differently, this disagrees.
        const UInt64 timeSigned  = 1_700_000_000;
        const UInt16 fudge       = 300;

        var message  = Query();
        var expected = new List<Byte>();

        expected.AddRange(message);
        expected.AddRange(CanonicalWire("test-key."));                       // NAME
        expected.AddRange([0x00, 0xFF]);                                     // CLASS = ANY
        expected.AddRange([0x00, 0x00, 0x00, 0x00]);                         // TTL   = 0
        expected.AddRange(CanonicalWire("hmac-sha256."));                    // Algorithm
        expected.AddRange([0x00, 0x00]);                                     // Time signed, high 16
        expected.AddRange(BigEndian32((UInt32) timeSigned));                 // Time signed, low 32
        expected.AddRange(BigEndian16(fudge));                               // Fudge
        expected.AddRange([0x00, 0x00]);                                     // Error
        expected.AddRange([0x00, 0x00]);                                     // Other len

        var reference = HMACSHA256.HashData(Secret, expected.ToArray());

        Assert.That(TSIGSigner.ComputeMAC(message, Key(), timeSigned, fudge, 0, []),
                    Is.EqualTo(reference),
                    "the MAC must be the HMAC of message || TSIG variables, in the order §4.3.3 gives");

    }

    #endregion

    #region Tampered_Message_Fails_With_BADSIG()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public void Tampered_Message_Fails_With_BADSIG()
    {

        var signed = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);

        // Flip a bit inside the question section — the part the MAC covers.
        signed[15] ^= 0x01;

        var result = TSIGSigner.Verify(signed, Key(), Now: 1_700_000_000);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False, "a message altered in flight must not verify");
            Assert.That(result.Error,   Is.EqualTo(TSIGSigner.BADSIG));
        });

    }

    #endregion

    #region Wrong_Secret_Fails_With_BADSIG()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public void Wrong_Secret_Fails_With_BADSIG()
    {

        var signed  = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);
        var other   = new TSIGKey(DomainName.Parse("test-key."), Encoding.ASCII.GetBytes("a different secret"));

        var result  = TSIGSigner.Verify(signed, other, Now: 1_700_000_000);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Error,   Is.EqualTo(TSIGSigner.BADSIG),
                        "the key name matches, so this is a bad signature rather than a bad key");
        });

    }

    #endregion

    #region Wrong_Key_Name_Fails_With_BADKEY()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public void Wrong_Key_Name_Fails_With_BADKEY()
    {

        var signed  = TSIGSigner.Sign(Query(), Key("one-key."), TimeSigned: 1_700_000_000);
        var result  = TSIGSigner.Verify(signed, Key("other-key."), Now: 1_700_000_000);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Error,   Is.EqualTo(TSIGSigner.BADKEY),
                        "a verifier that does not hold this key reports BADKEY, not BADSIG — " +
                        "the distinction is what lets the sender tell a misconfiguration from an attack");
        });

    }

    #endregion

    #region Time_Outside_The_Fudge_Window_Fails_With_BADTIME()

    [Test]
    [Property("RFC", "8945 §5.2.3")]
    [TestCase(1_700_000_299u, true,  TestName = "Time_Outside_The_Fudge_Window_Fails_With_BADTIME(just inside)")]
    [TestCase(1_700_000_301u, false, TestName = "Time_Outside_The_Fudge_Window_Fails_With_BADTIME(just outside)")]
    [TestCase(1_699_999_699u, false, TestName = "Time_Outside_The_Fudge_Window_Fails_With_BADTIME(too far in the past)")]
    public void Time_Outside_The_Fudge_Window_Fails_With_BADTIME(UInt64 Now, Boolean ShouldVerify)
    {

        // Fudge is 300 s either side of the time signed. The window is symmetric:
        // a message from the future is as suspect as one from the past.
        var signed = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000, Fudge: 300);
        var result = TSIGSigner.Verify(signed, Key(), Now: Now);

        Assert.That(result.IsValid, Is.EqualTo(ShouldVerify), result.Description);

        if (!ShouldVerify)
            Assert.That(result.Error, Is.EqualTo(TSIGSigner.BADTIME),
                        "the MAC is fine; only the clock is not");

    }

    #endregion

    #region Rewritten_Message_Id_Still_Verifies()

    [Test]
    [Property("RFC", "8945 §5.3.1")]
    public void Rewritten_Message_Id_Still_Verifies()
    {

        var signed = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);

        // A forwarder is allowed to renumber a message in flight. The MAC was
        // taken over the original ID, and the TSIG carries it, so verification
        // has to restore it before recomputing — otherwise every forwarded
        // message fails for a reason that is not an attack.
        signed[0] = 0xBE;
        signed[1] = 0xEF;

        var result = TSIGSigner.Verify(signed, Key(), Now: 1_700_000_000);

        Assert.That(result.IsValid, Is.True,
                    $"a renumbered message must still verify: {result.Description}");

    }

    #endregion

    #region Response_Mac_Folds_In_The_Request_Mac()

    [Test]
    [Property("RFC", "8945 §4.3.1")]
    public void Response_Mac_Folds_In_The_Request_Mac()
    {

        var request     = TSIGSigner.Sign(Query(), Key(), TimeSigned: 1_700_000_000);
        var requestMAC  = TSIGSigner.Verify(request, Key(), Now: 1_700_000_000).MAC!;

        var response    = RawDnsWriter.Query(0x4711, "example.", RawDnsType.A);

        var boundToRequest = TSIGSigner.Sign(response, Key(), TimeSigned: 1_700_000_000, RequestMAC: requestMAC);
        var unbound        = TSIGSigner.Sign(response, Key(), TimeSigned: 1_700_000_000);

        Assert.Multiple(() => {

            Assert.That(boundToRequest, Is.Not.EqualTo(unbound),
                        "a response signed against a request must not equal one signed without it, " +
                        "or the response could be replayed to answer a different question");

            Assert.That(TSIGSigner.Verify(boundToRequest, Key(), Now: 1_700_000_000, RequestMAC: requestMAC).IsValid,
                        Is.True);

            Assert.That(TSIGSigner.Verify(boundToRequest, Key(), Now: 1_700_000_000).IsValid,
                        Is.False,
                        "verifying without the request MAC must fail — that is the binding doing its job");

        });

    }

    #endregion

    #region Unsigned_Message_Is_Not_Mistaken_For_A_Signed_One()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public void Unsigned_Message_Is_Not_Mistaken_For_A_Signed_One()
    {

        var result = TSIGSigner.Verify(Query(), Key(), Now: 1_700_000_000);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False, "an unsigned message is not authentic, it is merely unsigned");
            Assert.That(result.Error,   Is.EqualTo(TSIGSigner.BADSIG));
        });

    }

    #endregion

    #region Unsupported_Algorithm_Is_Refused_Rather_Than_Guessed()

    [Test]
    [Property("RFC", "8945 §6")]
    public void Unsupported_Algorithm_Is_Refused_Rather_Than_Guessed()
    {

        Assert.Multiple(() => {

            Assert.That(TSIGAlgorithms.IsSupported(TSIGAlgorithms.HMACSHA256), Is.True,
                        "§6 makes HMAC-SHA256 mandatory to implement");

            Assert.That(TSIGAlgorithms.IsSupported(DomainName.Parse("hmac-md5.sig-alg.reg.int.")), Is.False);

            Assert.That(() => TSIGAlgorithms.ComputeHMAC(DomainName.Parse("hmac-whirlpool."), Secret, [1, 2, 3]),
                        Throws.TypeOf<NotSupportedException>(),
                        "an unknown algorithm must not fall back to a default — that would authenticate " +
                        "with something the peer never agreed to");

        });

    }

    #endregion


    #region (private static) Helpers

    private static Byte[] CanonicalWire(String Name)
    {

        var stream = new MemoryStream();

        foreach (var label in Name.ToLowerInvariant().TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((Byte) bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0x00);

        return stream.ToArray();

    }

    private static Byte[] BigEndian16(UInt16 Value)
        => [ (Byte) (Value >> 8), (Byte) Value ];

    private static Byte[] BigEndian32(UInt32 Value)
        => [ (Byte) (Value >> 24), (Byte) (Value >> 16), (Byte) (Value >> 8), (Byte) Value ];

    #endregion

}
