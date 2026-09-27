using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// Asking for several record types at one name, and what the one answer says.
/// </summary>
/// <remarks>
/// <para>
/// RFC 1035 §4.1.2 gives a question exactly one QTYPE, so a caller asking for
/// three types is three queries however the API is shaped. The three answers
/// then have to become one, and the fields of that one are not all the same kind
/// of merge: the answer sections add up, the header bits do not, and the response
/// code belongs to whichever of the three is allowed to speak for the whole.
/// </para>
/// <para>
/// Which is the interesting one, because the three may disagree. A name can have
/// an A record and no TXT record, and it can have an A record while the server
/// fails on TXT — and in both cases the caller asked a question that was answered.
/// </para>
/// </remarks>
[TestFixture]
public class MultiTypeQueryTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(800);


    private static DNSClient ClientFor(Int32 Port)
        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Port),
                QueryTimeout:   ShortTimeout,
                UseQueryCache:  false);

    #endregion


    #region Which of several answers speaks for the whole (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1, §4.1.2")]
    public async Task An_Answer_Is_Not_Overruled_By_A_Failure_Beside_It()
    {

        // Two types at one name: A is answered, TXT comes back NXDOMAIN. RFC 1035
        // §4.1.1 makes that response code mean "the domain name referenced in the
        // query does not exist" — which the A answer, from the same name and the
        // same server, disproves.
        //
        // So the merged answer cannot take its response code from whichever query
        // happened to fail. The pair is contradictory on its face: an answer
        // section with a record in it under a header saying the name is not there.
        // A caller reading the code first discards the record; one reading the
        // records first ignores the code; a caller that caches the negative caches
        // the denial of a name it was simultaneously told about.
        await using var server = new ScriptedUdpServer(request => {

            var question = RawDnsReader.Parse(request).Questions[0];

            return question.Type == RawDnsType.A
                       ? RawDnsResponder.Answer(request, ($"{question.Name.Canonical}.", RawDnsType.A, 300, [192, 0, 2, 4]))
                       : RawDnsResponder.Rcode(request, 3);   // NXDOMAIN for everything else

        });

        using var client = ClientFor(server.Port);

        var answer = await client.Query(DNSServiceName.Parse("mixed.example."),
                                        [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.TXT ],
                                        ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(answer.ResponseCode, Is.EqualTo(DNSResponseCodes.NoError),
                        "one of the two types was answered, so the name exists and the merged code says so");

            Assert.That(answer.Answers.Any(record => record.Type == DNSResourceRecordTypes.A), Is.True,
                        "and the record that was answered is in it");

        });

    }

    #endregion

}
