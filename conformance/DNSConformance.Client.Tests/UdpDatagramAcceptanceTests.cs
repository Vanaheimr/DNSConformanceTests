using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// Which datagrams a UDP client may act on, and what it says when it never asked.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="UdpClientBehaviorTests"/> covers the spoofing case that RFC 5452
/// §4.2 is written for: a datagram with the wrong transaction ID must be ignored
/// and the genuine reply still awaited. What it does not cover is a datagram too
/// short to *have* the attributes §9.1 says must match — the ID is the first two
/// octets, and a datagram of exactly two octets can carry a matching one and
/// nothing else at all.
/// </para>
/// <para>
/// The question is not whether such a datagram is refused; everything refuses it
/// eventually. It is whether refusing it ends the query, which is the denial of
/// service the section exists to prevent.
/// </para>
/// </remarks>
[TestFixture]
public class UdpDatagramAcceptanceTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(900);


    private static DNSUDPClient ClientFor(Int32 Port)
        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Port),
                QueryTimeout: ShortTimeout);

    #endregion


    #region A datagram with nothing but a matching id (RFC 5452 §4.2, §9.1)

    [Test]
    [Property("RFC", "5452 §4.2, §9.1")]
    public async Task A_Two_Octet_Datagram_With_The_Right_Id_Does_Not_End_The_Query()
    {

        // RFC 5452 §9.1 has a resolver match a response on "Query ID, Query name,
        // Query type, Query class". Two octets hold the ID and nothing else, so
        // three of the four attributes are not merely wrong but absent — and the
        // one that is present is the one an off-path attacker can guess, sixteen
        // bits of it.
        //
        // §4.2 then decides what refusing has to look like: ignoring means keep
        // waiting. A two-octet packet that ends the lookup is a denial of service
        // costing one datagram, which is cheaper than any spoof that has to get a
        // whole message right.
        await using var server = new ScriptedUdpServer((request, _) => new[] {
            new Byte[] { request[0], request[1] },
            RawDnsResponder.Answer(request, ("stub.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.77")))
        });

        await using var client = ClientFor(server.Port);

        var response = await client.Query<A>(DomainName.Parse("stub.example."), ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(response.IsValid, Is.True,
                        "§4.2: the genuine reply still arrives, because ignoring means waiting");

            Assert.That(response.FilteredAnswers.Select(record => record.IPv4Address.ToString()),
                        Is.EqualTo(new[] { "192.0.2.77" }),
                        "and it is the real answer that is delivered");

        });

    }

    #endregion


    #region A query with no name to ask about (RFC 1035 §4.1.2)

    [Test]
    [Property("RFC", "1035 §4.1.2, §4.1.1")]
    public async Task A_Query_Without_A_Name_Is_Answered_Rather_Than_Thrown()
    {

        // A question section entry is a name, a type and a class (RFC 1035 §4.1.2),
        // so there is no query to send without a name and nothing to put on the
        // wire. The client answers from where it stands instead, and what it says
        // about a message that was never sent is constrained the same way every
        // synthesized answer is: §4.1.1 makes AA a statement about the responding
        // name server and RA a statement about recursion support in it, and there
        // is no responding name server here.
        //
        // The assertion that no datagram left is what makes the rest mean anything:
        // without it a name error could equally be one a resolver sent back.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(request, ("never.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.1")))
        );

        await using var client = ClientFor(server.Port);

        // The cast picks the DNSServiceName overload: DomainName has one with the
        // same shape, and a bare null cannot say which guard is being aimed at.
        var response = await client.Query((DNSServiceName) null!,
                                          [ DNSResourceRecordTypes.A ],
                                          ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(server.Requests, Is.Empty,
                        "nothing can be asked, so nothing is sent");

            Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                        "a query with no name has no name that exists");

            Assert.That(response.AuthoritativeAnswer, Is.False,
                        "§4.1.1: AA says the responding name server is an authority, and none responded");

            Assert.That(response.RecursionAvailable, Is.False,
                        "§4.1.1: RA says recursion is available in the name server, and there is none");

            Assert.That(response.IsTruncated, Is.False,
                        "nothing was truncated because nothing was transmitted");

            Assert.That(response.IsTimeout, Is.False,
                        "the client did not run out of time, it declined to start");

            Assert.That(response.IsValid, Is.True,
                        "the answer is meant to be read rather than discarded");

        });

    }

    #endregion


    #region How the question section is written (RFC 1035 §4.1.4)

    [Test]
    [Property("RFC", "1035 §4.1.4, §4.1.2")]
    public async Task Each_Question_Carries_Its_Name_In_Full()
    {

        // Two types at one name become two questions in one message, and the
        // second one's name is a candidate for the compression RFC 1035 §4.1.4
        // describes: a pointer to the identical name already in the message.
        //
        // Legal on paper, and not what anything sends. §4.1.4 introduces pointers
        // "to reduce the size of messages" and the whole section is written around
        // repeated names in *resource records*; a query holds one name and gains
        // nothing. What it can lose is a responder that never had a reason to
        // handle a pointer inside a question, and the two octets saved are not
        // worth finding out which those are.
        //
        // This is behaviour rather than an RFC rule, which is why the assertion
        // says so and does not cite a MUST.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(request, ("both.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.2")))
        );

        await using var client = ClientFor(server.Port);

        await client.Query(DNSServiceName.Parse("both.example."),
                           [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                           ShortTimeout);

        Assert.That(server.Requests, Is.Not.Empty, "the query was sent");

        var query = RawDnsReader.Parse(server.Requests.First());

        Assert.Multiple(() => {

            Assert.That(query.Questions, Has.Count.EqualTo(2),
                        "both types travel in one message");

            Assert.That(query.Questions.All(question => !question.Name.Compressed), Is.True,
                        "and each question spells its name out rather than pointing at the other");

        });

    }

    #endregion

}
