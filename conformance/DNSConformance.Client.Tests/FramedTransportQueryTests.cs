using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What the two stream transports put on the wire, and what they accept back.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TcpFallbackAndFramingTests"/> covers the framing itself — the
/// two-octet prefix of RFC 7766 §8, reassembly of a dribbled response, connection
/// reuse, and a server closing the connection. What nothing covered is the message
/// inside the frame: which types were asked for, whether the recursion bit says
/// what the caller asked for, and how the question section is written.
/// </para>
/// <para>
/// `DNSTCPClient` and `DNSTLSClient` are separate classes with no common type to
/// test through, and their query paths are near-identical line for line. Every
/// test here therefore runs twice, which is the honest way round: a rule asserted
/// for one of two parallel implementations says nothing about the other, and the
/// sweep reports them as separate lines because they are.
/// </para>
/// </remarks>
[TestFixture]
public class FramedTransportQueryTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    private static readonly DNSResourceRecordTypes[] OneType  = [ DNSResourceRecordTypes.A ];
    private static readonly DNSResourceRecordTypes[] TwoTypes = [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ];


    private static Byte[] AnAnswer(Byte[] Request)
        => RawDnsResponder.Answer(Request, ("framed.example.", RawDnsType.A, 300, [192, 0, 2, 55]));


    /// <summary>
    /// Ask over TCP and hand back the query the server actually received.
    /// </summary>
    /// <param name="ClientRecursion">What the client is constructed with.</param>
    /// <param name="ClearClientRecursion">
    /// Whether to put the property back to null afterwards. The constructor resolves
    /// its argument with <c>?? true</c>, so the field is never null unless somebody
    /// sets it so — and the per-query fallback behind it cannot be reached any other
    /// way.
    /// </param>
    /// <param name="CallRecursion">What the call passes, which may also be null.</param>
    private static async Task<RawDnsMessage> OverTcp(Boolean?                   ClientRecursion        = null,
                                                     Boolean                    ClearClientRecursion   = false,
                                                     Boolean?                   CallRecursion          = true,
                                                     DNSResourceRecordTypes[]?  Types                  = null)
    {

        await using var server = new ScriptedTcpServer(AnAnswer);

        await using var client = new DNSTCPClient(IPv4Address.Localhost,
                                                  Port:              IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout:      Timeout,
                                                  RecursionDesired:  ClientRecursion);

        if (ClearClientRecursion)
            client.RecursionDesired = null;

        await client.Query(DNSServiceName.Parse("framed.example."),
                           Types ?? OneType,
                           Timeout,
                           CallRecursion);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the query reached the server");

        return RawDnsReader.Parse(request!);

    }


    /// <summary>The same over DoT.</summary>
    private static async Task<RawDnsMessage> OverTls(Boolean?                   ClientRecursion        = null,
                                                     Boolean                    ClearClientRecursion   = false,
                                                     Boolean?                   CallRecursion          = true,
                                                     DNSResourceRecordTypes[]?  Types                  = null)
    {

        await using var server = new ScriptedTlsServer(AnAnswer);

        await using var client = new DNSTLSClient(IPv4Address.Localhost,
                                                  TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout:                Timeout,
                                                  RecursionDesired:            ClientRecursion,
                                                  RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        if (ClearClientRecursion)
            client.RecursionDesired = null;

        await client.Query(DNSServiceName.Parse("framed.example."),
                           Types ?? OneType,
                           Timeout,
                           CallRecursion);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the query reached the server");

        return RawDnsReader.Parse(request!);

    }

    #endregion


    #region The recursion bit (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task The_Recursion_Bit_Says_What_The_Client_Was_Built_With()
    {

        // RFC 1035 §4.1.1: "RD - Recursion Desired - this bit may be set in a query
        // and is copied into the response." A stub resolver sets it; something
        // walking the delegation chain itself must not, because a recursive server
        // that honours RD answers from its own cache instead of referring downwards.
        // So the bit is the difference between two kinds of resolver, and it has to
        // follow what the caller asked for rather than a constant.
        // Awaited into locals first, on purpose. Assert.Multiple takes an Action, so
        // an async lambda handed to it becomes async void: it returns at the first
        // await, the block ends, and the assertions run detached from the test that
        // was supposed to be making them. A test green for that reason asserts
        // nothing at all.
        var tcpDefault  = (await OverTcp()).RD;
        var tcpOff      = (await OverTcp(ClientRecursion: false)).RD;
        var tlsDefault  = (await OverTls()).RD;
        var tlsOff      = (await OverTls(ClientRecursion: false)).RD;

        Assert.Multiple(() => {

            Assert.That(tcpDefault, Is.True,  "TCP, nothing said: a stub client asks for recursion");
            Assert.That(tcpOff,     Is.False, "TCP, switched off at construction: the bit is clear");
            Assert.That(tlsDefault, Is.True,  "DoT, nothing said");
            Assert.That(tlsOff,     Is.False, "DoT, switched off at construction");

        });

    }


    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Recursion_Left_Unset_Everywhere_Is_Still_Asked_For()
    {

        // Both the client property and the call take a nullable, and each has its
        // own fallback. The constructor's `?? true` makes the property non-null, so
        // the fallback behind it is unreachable until the property is put back to
        // null by hand — which is the only way to ask what the last `?? true`
        // decides. It decides in favour of recursion, which is the right default
        // for a stub and the one the parameter's own default already states.
        var overTcp = (await OverTcp(ClearClientRecursion: true, CallRecursion: null)).RD;
        var overTls = (await OverTls(ClearClientRecursion: true, CallRecursion: null)).RD;

        Assert.Multiple(() => {

            Assert.That(overTcp, Is.True,
                        "TCP: unset at the client and unset at the call still means recursion");

            Assert.That(overTls, Is.True, "DoT: the same");

        });

    }

    #endregion


    #region The question section (RFC 1035 §4.1.2, §4.1.4)

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public async Task The_Types_Asked_For_Are_The_Types_Sent()
    {

        // Two named types must travel as two questions of those types. The guard
        // that substitutes ANY exists for a caller who named none, and a client
        // that reached for it anyway would ask for everything at a name and then
        // filter — answering the question from a larger answer, over a transport
        // where the larger answer is never truncated to make it obvious.
        var overTcp = (await OverTcp(Types: TwoTypes)).Questions.Select(question => question.Type).ToArray();
        var overTls = (await OverTls(Types: TwoTypes)).Questions.Select(question => question.Type).ToArray();

        Assert.Multiple(() => {

            Assert.That(overTcp, Is.EquivalentTo(new UInt16[] { RawDnsType.A, RawDnsType.AAAA }),
                        "TCP asks for what it was told to ask for");

            Assert.That(overTls, Is.EquivalentTo(new UInt16[] { RawDnsType.A, RawDnsType.AAAA }),
                        "and so does DoT");

        });

    }


    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public async Task Each_Question_Carries_Its_Name_In_Full()
    {

        // Two types at one name make two questions, so the second name is a
        // candidate for the pointer §4.1.4 describes. Legal on paper, and sent by
        // nothing: the section is written around repeated names in resource
        // records, a query gains two octets, and what it can lose is a responder
        // that never had a reason to expect a pointer inside a question.
        //
        // Behaviour rather than a MUST, which is why this cites the section that
        // permits compression rather than one that forbids it here.
        var overTcp = (await OverTcp(Types: TwoTypes)).Questions.All(question => !question.Name.Compressed);
        var overTls = (await OverTls(Types: TwoTypes)).Questions.All(question => !question.Name.Compressed);

        Assert.Multiple(() => {

            Assert.That(overTcp, Is.True, "TCP spells both names out");
            Assert.That(overTls, Is.True, "and so does DoT");

        });

    }

    #endregion


    #region What comes back inside the frame (RFC 7766 §8, RFC 5452 §9.1)

    [Test]
    [Property("RFC", "7766 §8, 5452 §9.1, 1035 §4.1.1")]
    public async Task A_Framed_Response_Of_Exactly_The_Header_Is_Not_Accepted()
    {

        // RFC 7766 §8 puts a two-octet length in front of the message, so a framed
        // response can declare exactly twelve octets and be internally consistent:
        // RFC 1035 §4.1.1 makes the header that long, and a message of nothing else
        // is well-formed.
        //
        // It is still not an answer to this query. QDCOUNT is zero, and RFC 5452
        // §9.1 has a resolver match a response on "Query ID, Query name, Query
        // type, Query class" — three of which are absent rather than wrong. Over a
        // stream there is no next datagram to wait for, so the query ends; what it
        // must not do is end with an answer.
        var header = new RawDnsWriter().
                         Header(0,
                                (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA),
                                0, 0, 0, 0).
                         ToArray();

        Assert.That(header, Has.Length.EqualTo(12), "the header is twelve octets and this is only the header");

        await using var tcpServer = new ScriptedTcpServer(_ => header);

        await using var tcpClient = new DNSTCPClient(IPv4Address.Localhost,
                                                     Port:          IPPort.Parse((UInt16) tcpServer.Port),
                                                     QueryTimeout:  Timeout);

        var overTcp = await tcpClient.Query(DNSServiceName.Parse("framed.example."), OneType, Timeout);

        await using var tlsServer = new ScriptedTlsServer(_ => header);

        await using var tlsClient = new DNSTLSClient(IPv4Address.Localhost,
                                                     TCPPort:                     IPPort.Parse((UInt16) tlsServer.Port),
                                                     QueryTimeout:                Timeout,
                                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        var overTls = await tlsClient.Query(DNSServiceName.Parse("framed.example."), OneType, Timeout);

        Assert.Multiple(() => {

            Assert.That(overTcp.IsValid, Is.False,
                        "§9.1: a response with no question to match is not one a resolver may use");

            Assert.That(overTls.IsValid, Is.False,
                        "and the same over DoT");

        });

    }

    #endregion

}
