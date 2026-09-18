using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 2930 §4.1 and RFC 2539 — establishing a TSIG secret by Diffie-Hellman,
/// and the KEY record that carries the public values.
///
/// <para>
/// The derivation is checked against the formula applied by hand with MD5, not
/// against Hermod's own output. There are no published vectors for this
/// exchange — RFC 2930 gives the formula and no worked example — so the
/// specification text is the only independent reference available, and the
/// tests encode it directly.
/// </para>
/// </summary>
[TestFixture]
public class TkeyExchangeTests
{

    private static readonly Byte[] SharedSecret = Convert.FromHexString("0badc0ffee0ddf00d0badc0ffee0ddf00d");
    private static readonly Byte[] QueryNonce   = Encoding.ASCII.GetBytes("client-nonce");
    private static readonly Byte[] ServerNonce  = Encoding.ASCII.GetBytes("server-nonce");


    #region Keying_Material_Matches_The_Formula_Of_Section_4_1()

    [Test]
    [Property("RFC", "2930 §4.1")]
    public void Keying_Material_Matches_The_Formula_Of_Section_4_1()
    {

        //   keying material = XOR ( DH value,
        //                           MD5 ( query data | DH value ) |
        //                           MD5 ( server data | DH value ) )
        //
        // Assembled here straight from the specification. Every detail below is
        // a way to get it wrong while still producing 32 plausible octets: which
        // operand is suffixed to which, whether the digests are concatenated or
        // XORed with each other, and which nonce comes first.
        var expectedDigests = new Byte[32];

        Buffer.BlockCopy(MD5.HashData([.. QueryNonce,  .. SharedSecret]), 0, expectedDigests,  0, 16);
        Buffer.BlockCopy(MD5.HashData([.. ServerNonce, .. SharedSecret]), 0, expectedDigests, 16, 16);

        var expected = new Byte[32];
        for (var i = 0; i < 32; i++)
            expected[i] = (Byte) ((i < SharedSecret.Length ? SharedSecret[i] : 0) ^ expectedDigests[i]);

        Assert.That(TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce, ServerNonce),
                    Is.EqualTo(expected));

    }

    #endregion

    #region A_Shared_Secret_Longer_Than_The_Digests_Keeps_Its_Length()

    /// <summary>
    /// RFC 2930 §4.1's formula XORs the DH value against two MD5 digests joined,
    /// which is always 32 octets — and a real DH value is much longer than that:
    /// the smallest modulus RFC 2539 contemplates gives 128. So the ordinary case
    /// is the one where the right-hand operand runs out first, and §4.1 says what
    /// happens then: the shorter is left-justified, its missing tail treated as
    /// zero, and the result keeps the length of the longer.
    ///
    /// Past octet 32 the keying material is therefore the DH value unchanged,
    /// which is what makes the tail checkable without recomputing anything.
    /// </summary>
    [Test]
    [Property("RFC", "2930 §4.1")]
    public void A_Shared_Secret_Longer_Than_The_Digests_Keeps_Its_Length()
    {

        // 128 octets: a 1024-bit modulus, the smallest that is any use.
        var shared = new Byte[128];
        for (var i = 0; i < shared.Length; i++)
            shared[i] = (Byte) (i + 1);

        var keying = TKEYExchange.DeriveKeyingMaterial(shared,
                                                       Encoding.ASCII.GetBytes("query"),
                                                       Encoding.ASCII.GetBytes("server"));

        Assert.Multiple(() => {

            Assert.That(keying, Has.Length.EqualTo(128),
                        "the result is as long as the longer operand");

            Assert.That(keying[32..], Is.EqualTo(shared[32..]),
                        "and past the digests it is the DH value XORed with nothing");

            Assert.That(keying[..32], Is.Not.EqualTo(shared[..32]),
                        "while the first thirty-two octets did meet a digest");

        });

    }

    #endregion

    #region Both_Sides_Derive_The_Same_Key()

    [Test]
    [Property("RFC", "2930 §4.1")]
    public void Both_Sides_Derive_The_Same_Key()
    {

        // The whole point of the exchange: client and server run the same
        // derivation over the same three inputs and must land on one secret.
        var client = TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce, ServerNonce);
        var server = TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce, ServerNonce);

        Assert.That(client, Is.EqualTo(server));

    }

    #endregion

    #region Nonce_Order_Is_Not_Interchangeable()

    [Test]
    [Property("RFC", "2930 §4.1")]
    public void Nonce_Order_Is_Not_Interchangeable()
    {

        // The query nonce is digested first and the server nonce second. An
        // implementation that swapped them would agree with itself perfectly and
        // with no other implementation at all — the failure mode that a
        // self-consistency test cannot catch.
        Assert.That(TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce,  ServerNonce),
                    Is.Not.EqualTo(
                    TKEYExchange.DeriveKeyingMaterial(SharedSecret, ServerNonce, QueryNonce)));

    }

    #endregion

    #region A_Different_Shared_Secret_Yields_A_Different_Key()

    [Test]
    [Property("RFC", "2930 §4.1")]
    public void A_Different_Shared_Secret_Yields_A_Different_Key()
    {

        var other = (Byte[]) SharedSecret.Clone();
        other[0] ^= 0x01;

        Assert.That(TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce, ServerNonce),
                    Is.Not.EqualTo(
                    TKEYExchange.DeriveKeyingMaterial(other,        QueryNonce, ServerNonce)));

    }

    #endregion

    #region Derived_Key_Actually_Signs_And_Verifies()

    [Test]
    [Property("RFC", "2930 §4.1")]
    public void Derived_Key_Actually_Signs_And_Verifies()
    {

        // The exchange exists to produce a TSIG key, so the test that matters is
        // whether the result works as one. Client derives, signs; server derives
        // independently, verifies.
        var clientKey = new TSIGKey(DomainName.Parse("tkey-derived."),
                                    TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce, ServerNonce));

        var serverKey = new TSIGKey(DomainName.Parse("tkey-derived."),
                                    TKEYExchange.DeriveKeyingMaterial(SharedSecret, QueryNonce, ServerNonce));

        var signed    = TSIGSigner.Sign(RawDnsWriter.Query(0x2930, "example.", RawDnsType.A),
                                        clientKey,
                                        TimeSigned: 1_700_000_000);

        Assert.That(TSIGSigner.Verify(signed, serverKey, Now: 1_700_000_000).IsValid, Is.True,
                    "a key derived by both sides must authenticate a message between them");

    }

    #endregion

    #region Key_Rdata_Round_Trips_Through_Rfc_2539_Encoding()

    [Test]
    [Property("RFC", "2539 §2")]
    public void Key_Rdata_Round_Trips_Through_Rfc_2539_Encoding()
    {

        var prime       = Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234");
        var generator   = new Byte[] { 0x02 };
        var publicValue = Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF");

        var rdata       = TKEYExchange.EncodeDiffieHellmanKey(prime, generator, publicValue);

        Assert.Multiple(() => {

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey(rdata, out var p, out var g, out var pub), Is.True);
            Assert.That(p,   Is.EqualTo(prime));
            Assert.That(g,   Is.EqualTo(generator));
            Assert.That(pub, Is.EqualTo(publicValue));

            // Three 2-octet length prefixes plus the three values.
            Assert.That(rdata, Has.Length.EqualTo(6 + prime.Length + generator.Length + publicValue.Length));

        });

    }

    #endregion

    #region Well_Known_Group_Indices_Are_Refused_Rather_Than_Read_As_A_Prime()

    [Test]
    [Property("RFC", "2539 §2")]
    public void Well_Known_Group_Indices_Are_Refused_Rather_Than_Read_As_A_Prime()
    {

        // A prime length of 1 or 2 means "this field is an index into a table of
        // well-known groups", not "here is a one-octet prime". Reading it as a
        // modulus would silently produce a key derived from the wrong group.
        var withIndex = new Byte[] { 0x00, 0x01, 0x07,          // prime length 1 → group index 7
                                     0x00, 0x00,                // generator length 0
                                     0x00, 0x01, 0x42 };        // public value

        Assert.Multiple(() => {

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey(withIndex, out _, out _, out _), Is.False,
                        "a well-known-group index must not be decoded as a literal prime");

            Assert.That(() => TKEYExchange.EncodeDiffieHellmanKey([0x07], [0x02], [0x42]),
                        Throws.TypeOf<ArgumentException>(),
                        "and a one-octet prime cannot be encoded, because it would read back as an index");

        });

    }

    #endregion

    #region Truncated_Key_Rdata_Is_Rejected()

    [Test]
    [Property("RFC", "2539 §2")]
    public void Truncated_Key_Rdata_Is_Rejected()
    {

        var complete = TKEYExchange.EncodeDiffieHellmanKey(
                           Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234"),
                           [0x02],
                           Convert.FromHexString("0123456789ABCDEF")
                       );

        Assert.Multiple(() => {

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey(complete[..^1], out _, out _, out _), Is.False,
                        "a value cut short must not decode");

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey([.. complete, 0x00], out _, out _, out _), Is.False,
                        "and neither must one with bytes left over — trailing data means the lengths lied");

        });

    }

    #endregion

    #region Rdata_Too_Short_To_Hold_A_Length_Prefix_Is_Rejected()

    /// <summary>
    /// RFC 2539 §2 length-prefixes each of the three values with two octets, so
    /// the smallest thing that can be read at all is two octets. The cases above
    /// all cut a value's *body* short; these cut the length itself, which is a
    /// different failure and a different line.
    /// </summary>
    [Test]
    [Property("RFC", "2539 §2")]
    public void Rdata_Too_Short_To_Hold_A_Length_Prefix_Is_Rejected()
    {

        Assert.Multiple(() => {

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey([], out _, out _, out _), Is.False,
                        "no octets is not a prime with a length");

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey([0x00], out _, out _, out _), Is.False,
                        "and half a length prefix is not one either");

            // The same cut, one field further in: prime and generator are whole
            // and the public value is missing altogether. What makes this worth a
            // case of its own is that the reader stops exactly at the end of the
            // data, so the outer "did the lengths add up" check agrees with it and
            // cannot be what refuses the message.
            Byte[] noPublicValue = [0x00, 0x10, .. Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234"),
                                    0x00, 0x01, 0x02];

            Assert.That(noPublicValue, Has.Length.EqualTo(21));

            Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey(noPublicValue, out _, out _, out _), Is.False,
                        "a prime and a generator are not a Diffie-Hellman key");

        });

    }

    #endregion

    #region A_Length_With_Nothing_Behind_It_Is_Rejected()

    /// <summary>
    /// The other end of the same idea: the length prefix is there, it is the last
    /// thing in the RDATA, and it promises octets that are not. A reader that
    /// took the promise would hand back a public value of null while saying it
    /// had decoded one.
    /// </summary>
    [Test]
    [Property("RFC", "2539 §2")]
    public void A_Length_With_Nothing_Behind_It_Is_Rejected()
    {

        Byte[] promisesFive = [0x00, 0x10, .. Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234"),
                               0x00, 0x01, 0x02,
                               0x00, 0x05];

        Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey(promisesFive, out _, out _, out var publicValue),
                    Is.False,
                    "five octets are promised and none follow");

        Assert.That(publicValue, Is.Null,
                    "and nothing is handed back that a caller might use");

    }

    #endregion

    #region A_Value_Of_No_Octets_Is_Still_A_Value()

    /// <summary>
    /// RFC 2539 §2 gives each of the three values a length and sets no minimum,
    /// so a length of zero is well formed: the field is present and empty. It is
    /// the one input where the two guards in the reader disagree about what they
    /// are for — there is room for the length octets and no body to fit — and a
    /// reader that conflates them refuses a structure the format allows.
    /// </summary>
    [Test]
    [Property("RFC", "2539 §2")]
    public void A_Value_Of_No_Octets_Is_Still_A_Value()
    {

        Byte[] emptyPublicValue = [0x00, 0x10, .. Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234"),
                                   0x00, 0x01, 0x02,
                                   0x00, 0x00];

        Assert.That(TKEYExchange.TryDecodeDiffieHellmanKey(emptyPublicValue,
                                                           out var prime, out var generator, out var publicValue),
                    Is.True,
                    "the length octets are there and they say zero");

        Assert.Multiple(() => {
            Assert.That(prime,       Has.Length.EqualTo(16));
            Assert.That(generator,   Is.EqualTo(new Byte[] { 0x02 }));
            Assert.That(publicValue, Is.Empty);
        });

    }

    #endregion

    #region Key_Record_Round_Trips_On_The_Wire()

    [Test]
    [Property("RFC", "2535 §3")]
    public void Key_Record_Round_Trips_On_The_Wire()
    {

        var publicKey = TKEYExchange.EncodeDiffieHellmanKey(
                            Convert.FromHexString("FFFFFFFFFFFFFFFFC90FDAA22168C234"),
                            [0x02],
                            Convert.FromHexString("0123456789ABCDEF")
                        );

        var record    = new KEY(DomainName.Parse("tkey.example."),
                                DNSQueryClasses.IN,
                                TimeSpan.FromSeconds(300),
                                0x0000,
                                KEY.ProtocolDNSSEC,
                                KEY.AlgorithmDiffieHellman,
                                publicKey);

        var encoded   = RRWire.Encode(record);

        Assert.Multiple(() => {

            Assert.That(encoded.Type,        Is.EqualTo((UInt16) 25), "KEY is TYPE 25");
            Assert.That(encoded.Rdata[0..2], Is.EqualTo(new Byte[] { 0x00, 0x00 }), "flags");
            Assert.That(encoded.Rdata[2],    Is.EqualTo(3),           "RFC 3445 §4 fixes protocol at 3");
            Assert.That(encoded.Rdata[3],    Is.EqualTo(2),           "RFC 2539 assigns Diffie-Hellman algorithm 2");
            Assert.That(encoded.Rdata[4..],  Is.EqualTo(publicKey));

        });

    }

    #endregion

    #region No_Key_Is_Distinguishable_From_A_Key_That_Is_Merely_Unusable()

    [Test]
    [Property("RFC", "2535 §3.1.2")]
    public void No_Key_Is_Distinguishable_From_A_Key_That_Is_Merely_Unusable()
    {

        // Both use bits set means "no key information" — the record asserts the
        // name has no key at all, rather than carrying one that happens to be
        // restricted. One bit set is a real key with one use forbidden.
        var noKey      = new KEY(DomainName.Parse("k.example."), DNSQueryClasses.IN, TimeSpan.Zero,
                                 0xC000, KEY.ProtocolDNSSEC, 0, []);

        var authOnly   = new KEY(DomainName.Parse("k.example."), DNSQueryClasses.IN, TimeSpan.Zero,
                                 0x4000, KEY.ProtocolDNSSEC, KEY.AlgorithmDiffieHellman, [1, 2, 3]);

        Assert.Multiple(() => {

            Assert.That(noKey.IsNoKey,                     Is.True);
            Assert.That(authOnly.IsNoKey,                  Is.False);
            Assert.That(authOnly.ConfidentialityProhibited, Is.True);
            Assert.That(authOnly.AuthenticationProhibited,  Is.False);

        });

    }

    #endregion

}
