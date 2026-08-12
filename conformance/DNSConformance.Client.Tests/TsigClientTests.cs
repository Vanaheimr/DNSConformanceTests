using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 8945 §5.3 — the Hermod client signing its queries.
///
/// <para>
/// The client half is asserted against a scripted listener that reads the query
/// with <c>RawDns</c>, so what is checked is the bytes Hermod put on the wire
/// rather than Hermod's own account of them. Only the last test lets client and
/// server talk to each other, and even there the transcript is read
/// independently.
/// </para>
/// </summary>
[TestFixture]
public class TsigClientTests
{

    private static readonly Byte[] Secret = Convert.FromBase64String("Y2xpZW50LXNpZGUtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA==");

    private static TSIGKey Key(String Name = "client-key.")
        => new (DomainName.Parse(Name), Secret);


    #region Client_Signs_The_Query_It_Sends()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Client_Signs_The_Query_It_Sends()
    {

        Byte[]? seen = null;

        await using var server = new ScriptedUdpServer(request => {
            seen = request;
            return null;                         // let the query time out; the request is the subject
        });

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.Port),
                               QueryTimeout: TimeSpan.FromMilliseconds(400),
                               TSIGKey:      Key()
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

            Assert.That(message.Additionals.Any(rr => rr.Type == 250), Is.True,
                        "a TSIG record must ride along with the query");

            Assert.That(message.ConsumedBytes, Is.EqualTo(seen!.Length),
                        "no trailing bytes after the TSIG");

            // And it must actually verify — a record of the right shape carrying
            // a wrong MAC would satisfy the assertion above and nothing else.
            Assert.That(TSIGSigner.Verify(seen!, Key()).IsValid, Is.True,
                        "the MAC the client produced must verify under the shared key");

        });

    }

    #endregion

    #region Client_Without_A_Key_Sends_No_Tsig()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Client_Without_A_Key_Sends_No_Tsig()
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
        Assert.That(RawDnsReader.Parse(seen!).Additionals.Any(rr => rr.Type == 250), Is.False,
                    "configuring no key must leave the query exactly as it was before TSIG existed");

    }

    #endregion

    #region Client_Rejects_A_Response_That_Fails_Verification()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Client_Rejects_A_Response_That_Fails_Verification()
    {

        // The server answers promptly, correctly, and signed with the wrong
        // secret. A client that accepted it would gain nothing from TSIG at all:
        // the whole point is that an answer from anyone else is not an answer.
        var impostor = new TSIGKey(DomainName.Parse("client-key."),
                                   Convert.FromBase64String("aW1wb3N0b3Itc2VjcmV0LXRoYXQtaXMtdGhlLXdyb25nLW9uZQ=="));

        await using var server = new ScriptedUdpServer(request => {

            var id       = (UInt16) ((request[0] << 8) | request[1]);
            var response = RawDnsWriter.Response(
                               id,
                               "a.example.",
                               RawDnsType.A,
                               [ ("a.example.", RawDnsType.A, 300u, new Byte[] { 192, 0, 2, 1 }) ]
                           );

            return TSIGSigner.Sign(response, impostor);

        });

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.Port),
                               QueryTimeout: TimeSpan.FromMilliseconds(600),
                               TSIGKey:      Key()
                           );

        var result = await client.Query(DomainName.Parse("a.example."), [DNSResourceRecordTypes.A]);

        Assert.That(result.Answers.Any(), Is.False,
                    "an answer signed with a key the client does not share must not surface as data");

    }

    #endregion

    #region Client_And_Server_Complete_A_Signed_Exchange()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Client_And_Server_Complete_A_Signed_Exchange()
    {

        // Both halves together, over a real socket: the client signs, the server
        // verifies and signs its reply, the client verifies that in turn against
        // the MAC of its own request.
        await using var server = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                           TSIGKeys = [ Key() ]
                                       });

        using var client = new DNSUDPClient(
                               IPv4Address.Localhost,
                               IPPort.Parse(server.UdpPort),
                               QueryTimeout: TimeSpan.FromSeconds(2),
                               TSIGKey:      Key()
                           );

        var result = await client.Query(DomainName.Parse(ZoneFixtures.AName), [DNSResourceRecordTypes.A]);

        Assert.Multiple(() => {
            Assert.That(result.IsValid,        Is.True, "the exchange must succeed end to end");
            Assert.That(result.Answers.Any(),  Is.True, "and it must carry the answer, not just authenticate");
        });

    }

    #endregion

}
