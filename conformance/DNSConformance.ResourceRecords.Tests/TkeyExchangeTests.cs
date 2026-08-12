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
