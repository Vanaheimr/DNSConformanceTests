using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What a JSON answer says about itself, what a JSON question looks like, and
/// how several of them become one answer.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="JsonAnswerTests"/> asks whether the records of a JSON answer
/// arrive. This asks about everything around them. A wire-format answer carries
/// its flags in a header with no room for absence: every bit is set or clear. A
/// JSON answer carries them as named fields, and a field can be missing — so a
/// JSON reader decides, for every flag, what silence means.
/// </para>
/// <para>
/// The rule this file holds it to is the one a header would have imposed: a
/// flag the resolver did not state is not set. For AD that is a security
/// property rather than a convention. RFC 4035 §3.2.3 has a resolver set AD only
/// for data it has validated, so a client reading AD into an answer that never
/// claimed it would be inventing a validation nobody performed. RD is the one
/// exception, for a reason of its own: RFC 1035 §4.1.1 has the bit "copied into
/// the response", so a response that does not repeat it still answered a query
/// that asked for recursion — and every query on this API does.
/// </para>
/// </remarks>
[TestFixture]
public class JsonHeaderTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private const String OneTxtAnswer = """{"name":"probe.example.","type":16,"TTL":60,"data":"\"a\""}""";


    private static DNSHTTPSClient ClientFor(ScriptedDoHServer Peer)
        => new (URL.Parse(Peer.Url),
                Mode:          DNSHTTPSMode.JSON,
                QueryTimeout:  Timeout);


    private static async Task<DNSInfo> Ask(String Json, params DNSResourceRecordTypes[] Types)
    {

        await using var peer    = new ScriptedDoHServer(_ => null) { JSONResponse = Json };
        await using var client  = ClientFor(peer);

        return await client.Query(DNSServiceName.Parse("probe.example."),
                                  Types.Length > 0 ? Types : [ DNSResourceRecordTypes.TXT ],
                                  Timeout);

    }

    #endregion


    #region The question

    [Test]
    public async Task A_Json_Question_Names_The_Name_And_The_Type()
    {

        // The JSON API has no DNS message to carry the question in, so the
        // question is the query string: ?name= and ?type=, both of them, and an
        // Accept naming the JSON media type rather than RFC 8484's. A request
        // carrying neither parameter is a question about nothing, and a resolver
        // answering it is answering something else.
        await using var peer   = new ScriptedDoHServer(_ => null) {
                                     JSONResponse = $$"""{"Status":0,"Answer":[{{OneTxtAnswer}}]}"""
                                 };
        await using var client = ClientFor(peer);

        await client.Query(DNSServiceName.Parse("probe.example."), [ DNSResourceRecordTypes.TXT ], Timeout);

        Assert.That(peer.Exchanges, Has.Count.EqualTo(1), "one question, one request");

        var exchange = peer.Exchanges.Single();

        Assert.Multiple(() => {
            Assert.That(exchange.Method,          Is.EqualTo("GET"));
            Assert.That(exchange.RawDnsParameter, Does.Contain("name=probe.example"), "the name asked about");
            Assert.That(exchange.RawDnsParameter, Does.Contain("type=16"),            "and the type, by number");
            Assert.That(exchange.Accept,          Does.Contain("application/dns-json"));
        });

    }

    #endregion


    #region The flags of the answer (RFC 1035 §4.1.1, RFC 4035 §3.2.3)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task The_Flags_A_Json_Answer_States_Are_The_Flags_Reported()
    {

        // The control for the test below it. Each flag set the other way round
        // from its default, so that reading it and ignoring it give different
        // answers — without this, a reader that hardcoded the defaults would pass
        // the next test for the wrong reason.
        var info = await Ask($$"""
                       {"Status":0,"TC":true,"RD":false,"RA":true,"AD":true,"CD":true,"Answer":[{{OneTxtAnswer}}]}
                       """);

        Assert.Multiple(() => {
            Assert.That(info.IsTruncated,        Is.True,  "TC");
            Assert.That(info.RecursionRequested, Is.False, "RD");
            Assert.That(info.RecursionAvailable, Is.True,  "RA");
            Assert.That(info.AuthenticData,      Is.True,  "AD");
            Assert.That(info.CheckingDisabled,   Is.True,  "CD");
        });

    }


    [Test]
    [Property("RFC", "1035 §4.1.1, 4035 §3.2.3")]
    public async Task A_Flag_A_Json_Answer_Leaves_Out_Is_Not_Assumed()
    {

        // The same answer with every flag left out. TC, RA, AD and CD are claims
        // the resolver makes, and a claim not made is not set: an answer read as
        // truncated, as from a recursive server, as validated or as unchecked is
        // an answer the resolver never gave. RD alone comes back true, because
        // it is the query's bit copied back and the query asked for recursion.
        var info = await Ask($$"""
                       {"Status":0,"Answer":[{{OneTxtAnswer}}]}
                       """);

        Assert.Multiple(() => {
            Assert.That(info.IsTruncated,        Is.False, "TC not stated: not truncated");
            Assert.That(info.RecursionRequested, Is.True,  "RD not repeated: still the recursion that was asked for");
            Assert.That(info.RecursionAvailable, Is.False, "RA not stated: not claimed");
            Assert.That(info.AuthenticData,      Is.False, "AD not stated: nothing was validated that the client knows of");
            Assert.That(info.CheckingDisabled,   Is.False, "CD not stated: not set");
        });

    }


    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Json_Answer_Is_A_Valid_Answer_And_Not_An_Authoritative_One()
    {

        // There is no AA field in this API at all, and the resolvers behind it
        // are recursive: nothing in a JSON answer can say it came from the zone's
        // own server, so it must not say so. Beside that, the answer is a real
        // one — read, not timed out — which is what tells it apart from the
        // failures this transport reports.
        var info = await Ask($$"""
                       {"Status":0,"RA":true,"AD":true,"Answer":[{{OneTxtAnswer}}]}
                       """);

        Assert.Multiple(() => {
            Assert.That(info.AuthoritativeAnswer, Is.False, "no field says AA, so AA is clear");
            Assert.That(info.IsValid,             Is.True,  "a parsed answer is a valid one");
            Assert.That(info.IsTimeout,           Is.False, "and it did not time out");
            Assert.That(info.Answers.Count(),     Is.EqualTo(1));
        });

    }

    #endregion


    #region A record with nothing to own it (RFC 1035 §3.2.1)

    [Test]
    [Property("RFC", "1035 §3.2.1")]
    public async Task A_Json_Record_Without_A_Name_Is_Dropped_And_Not_Placed_At_The_Root()
    {

        // RFC 1035 §3.2.1 begins every resource record with its NAME. A JSON
        // record without one has no owner, and the reader cannot supply one: the
        // nearest thing to a default is the root, and an A record at "." is a
        // record nobody published. So it is dropped, and the well-formed record
        // beside it is kept — dropping the whole answer would turn one bad entry
        // into NODATA.
        var info = await Ask($$"""
                       {"Status":0,"Answer":[
                           {"type":1,"TTL":60,"data":"192.0.2.1"},
                           {"name":"probe.example.","type":16,"TTL":60},
                           {{OneTxtAnswer}}
                       ]}
                       """);

        Assert.Multiple(() => {

            Assert.That(info.Answers.Count(), Is.EqualTo(1),
                        "one record of three has both a name and data");

            Assert.That(info.Answers.All(record => record is not null), Is.True,
                        "and nothing missing stands in its place");

            Assert.That(info.Answers.First().DomainName.FullName.TrimEnd('.'),
                        Is.EqualTo("probe.example").IgnoreCase,
                        "the one kept is the one that named itself");

        });

    }

    #endregion


    #region Several types, one question each (RFC 1035 §4.1.2)

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public async Task Several_Types_Over_Json_Are_Asked_One_By_One_And_Merged()
    {

        // The JSON API takes one type per request, so a caller asking for two is
        // two requests, and the caller gets one answer holding both. The server
        // here gives the same answer to each, which is enough to tell "merged"
        // from "the last one" and from "the first one".
        await using var peer   = new ScriptedDoHServer(_ => null) {
                                     JSONResponse = $$"""{"Status":0,"Answer":[{{OneTxtAnswer}}]}"""
                                 };
        await using var client = ClientFor(peer);

        var info = await client.Query(DNSServiceName.Parse("probe.example."),
                                      [ DNSResourceRecordTypes.TXT, DNSResourceRecordTypes.A ],
                                      Timeout);

        var types = peer.Exchanges.Select(exchange => exchange.RawDnsParameter ?? "").ToArray();

        Assert.Multiple(() => {

            Assert.That(types, Has.Length.EqualTo(2), "two types, two requests");
            Assert.That(types.Any(query => query.Contains("type=16")), Is.True, "one for TXT");
            Assert.That(types.Any(query => query.Contains("type=1&") || query.EndsWith("type=1")), Is.True, "one for A");

            Assert.That(info.ResponseCode,     Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(info.Answers.Count(),  Is.EqualTo(2), "and the answer holds what both of them returned");

        });

    }


    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Name_Error_Ends_A_Json_Fan_Out()
    {

        // RFC 1035 §4.1.1: NXDOMAIN means "the domain name referenced in the query
        // does not exist". Not for this type — at all. Every further type asked
        // about that name has the same answer already, so asking is a request the
        // resolver answers for nothing, and the answer the caller gets is that
        // name error rather than a merge that dilutes it.
        await using var peer   = new ScriptedDoHServer(_ => null) {
                                     JSONResponse = """{"Status":3,"Answer":[]}"""
                                 };
        await using var client = ClientFor(peer);

        var info = await client.Query(DNSServiceName.Parse("missing.example."),
                                      [ DNSResourceRecordTypes.TXT, DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                      Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Exchanges,    Has.Count.EqualTo(1), "the first name error is the last request");
            Assert.That(info.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError));
        });

    }

    #endregion


    #region Where Google's two APIs live

    [Test]
    public void Google_Answers_Json_At_Resolve_And_Rfc8484_At_Dns_Query()
    {

        // Two different protocols behind one host name: Google's JSON API is at
        // /resolve and its RFC 8484 endpoint at /dns-query. Each one answers its
        // own format only, so a client that picked the path by the wrong mode
        // would ask every question in a language the endpoint does not speak.
        // Read off the client rather than off the network: building one makes no
        // connection.
        using var json  = DNSHTTPSClient.Google(Mode: DNSHTTPSMode.JSON);
        using var wire  = DNSHTTPSClient.Google();
        using var post  = DNSHTTPSClient.Google(Mode: DNSHTTPSMode.POST);

        Assert.Multiple(() => {
            Assert.That(json.RemoteURL.ToString(), Does.EndWith("/resolve"),   "JSON");
            Assert.That(wire.RemoteURL.ToString(), Does.EndWith("/dns-query"), "the default, GET");
            Assert.That(post.RemoteURL.ToString(), Does.EndWith("/dns-query"), "POST");
        });

    }

    #endregion

}
