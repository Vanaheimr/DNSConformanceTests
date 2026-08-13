using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 2931 §3 — the Hermod client signing its queries with SIG(0).
/// </summary>
/// <remarks>
/// <para>
/// The client half is asserted against a scripted listener that reads the query
/// with <c>RawDns</c>, so what is checked is the bytes Hermod put on the wire
/// rather than Hermod's account of them. Where a signature has to be judged, the
/// judging is done with the platform's own RSA over the data RFC 2931 §3.1
/// defines — not by handing the message back to the code that signed it.
/// </para>
/// </remarks>
[TestFixture]
public class Sig0ClientTests
{

    private const UInt16 SigType = 24;

    private static readonly DomainName ClientName = DomainName.Parse("client.conformance.test");


    /// <summary>
    /// Verify a SIG(0) the way a peer would: reassemble §3.1's signed data from
    /// the message on the wire and check it with the platform's RSA.
    /// </summary>
    private static Boolean VerifiesIndependently(Byte[] SignedMessage, SIG0Key Key)
    {

        var message = RawDnsReader.Parse(SignedMessage);
        var sig     = message.Additionals[^1];

        if (sig.Type != SigType)
            return false;

        // The signed data is the SIG RDATA up to but excluding the signature,
        // followed by the message with its SIG(0) removed and ARCOUNT put back.
        var rdata      = sig.Rdata;
        var signerAt   = 18;
        var offset     = signerAt;

        while (offset < rdata.Length && rdata[offset] != 0)
            offset += rdata[offset] + 1;

        offset++;                                  // the root label

        var rdataPrefix = rdata[..offset];         // fields + signer's name
        var signature   = rdata[offset..];

        // Everything before this record, with ARCOUNT decremented.
        var recordStart = sig.RdataOffset - 10 - (sig.Name.WireLength);
        var unsigned    = SignedMessage[..recordStart];

        unsigned[10] = (Byte) ((message.Additionals.Count - 1) >> 8);
        unsigned[11] = (Byte) ((message.Additionals.Count - 1) & 0xFF);

        // The verifying key is read out of the KEY record the signer publishes,
        // decoded here from RFC 3110 §2 rather than taken from the key object —
        // which is the same route a real verifier has, and which also checks that
        // the published record actually matches the signatures being made under
        // it. Getting it from the private key instead would verify a signature
        // against the thing that produced it and prove nothing about what a
        // verifier would see.
        var encoded       = Key.PublicKey.PublicKey;
        var exponentLen   = (Int32) encoded[0];
        var at            = 1;

        if (exponentLen == 0)
        {
            exponentLen = (encoded[1] << 8) | encoded[2];
            at          = 3;
        }

        using var rsa = RSA.Create();

        rsa.ImportParameters(new RSAParameters {
            Exponent = encoded[at..(at + exponentLen)],
            Modulus  = encoded[(at + exponentLen)..]
        });

        Byte[] signedData = [.. rdataPrefix, .. unsigned];

        return rsa.VerifyData(signedData,
                              signature,
                              HashAlgorithmName.SHA256,
                              RSASignaturePadding.Pkcs1);

    }


    #region Client_Signs_The_Query_It_Sends()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task Client_Signs_The_Query_It_Sends()
    {

        Byte[]? seen = null;

        await using var server = new ScriptedUdpServer(request => {
            seen = request;
            return null;                         // let the query time out; the request is the subject
        });

        var key = SIG0Key.Generate(ClientName);

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.Port),
                               QueryTimeout: TimeSpan.FromMilliseconds(400),
                               SIG0Key:      key
                           );

        try
        {
            await client.Query(DomainName.Parse("a.example."), [DNSResourceRecordTypes.A]);
        }
        catch (Exception)
        {
            // A timeout is the expected outcome — the scripted server answers nothing.
        }

        Assert.That(seen, Is.Not.Null, "the client must have sent something");

        var message = RawDnsReader.Parse(seen!);

        Assert.Multiple(() => {

            Assert.That(message.Additionals, Is.Not.Empty);
            Assert.That(message.Additionals[^1].Type, Is.EqualTo(SigType),
                        "§3: the SIG(0) is the last record in the additional section");

            Assert.That(message.Additionals[^1].Name.Presentation, Is.EqualTo("."), "root owner name");
            Assert.That(message.Additionals[^1].Class, Is.EqualTo((UInt16) 255),    "CLASS ANY");
            Assert.That(message.Additionals[^1].Ttl,   Is.Zero,                     "TTL zero");

            Assert.That(message.ConsumedBytes, Is.EqualTo(seen!.Length),
                        "no trailing bytes after the SIG(0)");

            // And it must actually verify. A record of the right shape carrying a
            // wrong signature satisfies every assertion above and nothing else.
            Assert.That(VerifiesIndependently(seen!, key), Is.True,
                        "the signature must verify over the data RFC 2931 §3.1 defines");

        });

    }

    #endregion

    #region Client_Without_A_Key_Sends_No_Sig0()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task Client_Without_A_Key_Sends_No_Sig0()
    {

        Byte[]? seen = null;

        await using var server = new ScriptedUdpServer(request => {
            seen = request;
            return null;
        });

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.Port),
                               QueryTimeout: TimeSpan.FromMilliseconds(400)
                           );

        try
        {
            await client.Query(DomainName.Parse("a.example."), [DNSResourceRecordTypes.A]);
        }
        catch (Exception)
        { }

        Assert.That(seen, Is.Not.Null);

        var message = RawDnsReader.Parse(seen!);

        Assert.That(message.Additionals.Any(rr => rr.Type == SigType), Is.False,
                    "an unconfigured client signs nothing — SIG(0) costs a public key operation per message (§2.4)");

    }

    #endregion

    #region The_Tcp_Retry_Carries_The_Same_Signature()

    [Test]
    [Property("RFC", "2931 §3.1, 7766 §5")]
    public async Task The_Tcp_Retry_Carries_The_Same_Signature()
    {

        // The failure this catches is silent, which is what makes it worth a
        // test. UDP answers TC=1, the client retries over TCP — and if the retry
        // is rebuilt from the query object instead of resigned, it arrives
        // unsigned. The server serves unsigned requests happily (RFC 2931 §3.1
        // does not require otherwise), so nothing anywhere reports an error and
        // an exchange the caller believes is authenticated simply is not.
        //
        // It is not a rare corner either: truncation is what happens when the
        // answer is large, and a signed zone's answers are large.
        Byte[]? overTcp = null;

        var key = SIG0Key.Generate(ClientName);

        var (udp, tcp) = await ScriptedServerPair.CreateAsync(
                             UdpResponder: request => RawDnsResponder.Truncated(request),
                             TcpResponder: request => {
                                 overTcp = request;
                                 return RawDnsResponder.Answer(request, ("a.example.", RawDnsType.A, 300, [192, 0, 2, 1]));
                             }
                         );

        await using var udpServer = udp;
        await using var tcpServer = tcp;

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(udp.Port),
                               QueryTimeout: TimeSpan.FromSeconds(3),
                               SIG0Key:      key
                           );

        await client.Query(DomainName.Parse("a.example."), [DNSResourceRecordTypes.A]);

        Assert.That(overTcp, Is.Not.Null, "the truncated answer must have triggered a TCP retry");

        var retry = RawDnsReader.Parse(overTcp!);

        Assert.Multiple(() => {

            Assert.That(retry.Additionals, Is.Not.Empty);
            Assert.That(retry.Additionals[^1].Type, Is.EqualTo(SigType),
                        "the retry must carry a SIG(0) too");

            Assert.That(VerifiesIndependently(overTcp!, key), Is.True,
                        "…and one that actually verifies, not a copied record over different bytes");

        });

    }

    #endregion

    #region A_Response_Signature_That_Does_Not_Verify_Is_Discarded()

    [Test]
    [Property("RFC", "2931 §3.2")]
    public async Task A_Response_Signature_That_Does_Not_Verify_Is_Discarded()
    {

        // A client that was given the server's KEY has said it wants the reply
        // checked. A reply signed by somebody else must then not be believed —
        // and discarding it rather than failing outright is the same posture
        // RFC 5452 §4.2 takes for a mismatched transaction id: one forged
        // datagram must not be able to end a query.
        var serverKey  = SIG0Key.Generate(DomainName.Parse("server.conformance.test"));
        var impostor   = SIG0Key.Generate(DomainName.Parse("server.conformance.test"));

        await using var server = new ScriptedUdpServer(request =>
            SIG0Signer.Sign(
                RawDnsResponder.Answer(request, ("a.example.", RawDnsType.A, 300, [192, 0, 2, 1]))!,
                impostor,
                Request: request
            )
        );

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.Port),
                               QueryTimeout:    TimeSpan.FromMilliseconds(700),
                               SIG0Key:         SIG0Key.Generate(ClientName),
                               SIG0ServerKeys:  [ serverKey.PublicKey ]
                           );

        var response = await client.Query(DomainName.Parse("a.example."), [DNSResourceRecordTypes.A]);

        Assert.That(response.Answers.Any(), Is.False,
                    "a response signed by the wrong key is not an answer");

    }

    #endregion

    #region An_Unverifiable_Response_Signature_Is_Ignored_Without_A_Key()

    [Test]
    [Property("RFC", "2931 §3.2")]
    public async Task An_Unverifiable_Response_Signature_Is_Ignored_Without_A_Key()
    {

        // §3.2: "If a resolver or server does not implement transaction and/or
        // request SIGs, it MUST ignore them without error where they are
        // optional." A client with no server KEY configured cannot check the
        // signature, so it strips it and reads the answer — refusing here would
        // break interoperability with every server that signs opportunistically.
        var serverKey = SIG0Key.Generate(DomainName.Parse("server.conformance.test"));

        await using var server = new ScriptedUdpServer(request =>
            SIG0Signer.Sign(
                RawDnsResponder.Answer(request, ("a.example.", RawDnsType.A, 300, [192, 0, 2, 1]))!,
                serverKey,
                Request: request
            )
        );

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.Port),
                               QueryTimeout: TimeSpan.FromSeconds(2),
                               SIG0Key:      SIG0Key.Generate(ClientName)
                           );

        var response = await client.Query(DomainName.Parse("a.example."), [DNSResourceRecordTypes.A]);

        Assert.Multiple(() => {

            Assert.That(response.Answers.Any(), Is.True,
                        "the answer must come through");

            Assert.That(response.Answers.Any(rr => rr.Type == DNSResourceRecordTypes.SIG), Is.False,
                        "and the meta-RR must not leak into it — a SIG(0) is never part of an answer");

        });

    }

    #endregion

    #region Client_And_Server_Complete_A_Signed_Exchange()

    [Test]
    [Property("RFC", "2931 §3")]
    public async Task Client_And_Server_Complete_A_Signed_Exchange()
    {

        // End to end, with a real Hermod server on the other side: the client
        // signs, the server verifies and signs its reply, and the client verifies
        // that. Every step above tested one half against something independent;
        // this one is the check that the two halves actually meet.
        var clientKey = SIG0Key.Generate(ClientName);
        var serverKey = SIG0Key.Generate(DomainName.Parse("server.conformance.test"));

        await using var server = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                          SIG0Keys         = [ clientKey.PublicKey ],
                                          SIG0ResponseKey  = serverKey
                                      });

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.UdpPort),
                               QueryTimeout:    TimeSpan.FromSeconds(3),
                               SIG0Key:         clientKey,
                               SIG0ServerKeys:  [ serverKey.PublicKey ]
                           );

        var response = await client.Query(DomainName.Parse(ZoneFixtures.AName), [DNSResourceRecordTypes.A]);

        Assert.Multiple(() => {

            Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NoError));

            Assert.That(response.Answers.OfType<A>().Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse(ZoneFixtures.AAddress)),
                        "the answer survives both signatures intact");

        });

    }

    #endregion

    #region A_Wrong_Client_Key_Is_Refused_By_The_Server()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task A_Wrong_Client_Key_Is_Refused_By_The_Server()
    {

        var trusted = SIG0Key.Generate(ClientName);

        await using var server = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                          SIG0Keys = [ trusted.PublicKey ]
                                      });

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.UdpPort),
                               QueryTimeout: TimeSpan.FromSeconds(2),
                               SIG0Key:      SIG0Key.Generate(ClientName)   // same name, different pair
                           );

        var response = await client.Query(DomainName.Parse(ZoneFixtures.AName), [DNSResourceRecordTypes.A]);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,  Is.EqualTo(DNSResponseCodes.NotAuthorized), "NOTAUTH reaches the caller");
            Assert.That(response.Answers.Any(), Is.False);
        });

    }

    #endregion

}
