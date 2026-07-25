using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// An <see cref="IDNSClient"/> that answers from a canned table instead of a
/// socket, so <see cref="DNSSECValidator.ValidateAsync"/> can be driven through
/// every RFC 4035 §4.3 outcome offline and deterministically.
///
/// It resolves nothing on its own: whatever a test does not register is answered
/// as an empty NOERROR, which is exactly how a validator learns that a zone
/// publishes no DS and the delegation is therefore unsigned.
/// </summary>
public sealed class StubDnsClient : IDNSClient
{

    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), List<IDNSResourceRecord>> table = [];

    private static readonly DNSServerConfig origin = new(IPv4Address.Localhost, IPPort.DNS);


    /// <summary>Every query this client received, in order — for asserting what a validator asked for.</summary>
    public List<(String Name, DNSResourceRecordTypes Type)> Queries { get; } = [];

    /// <summary>
    /// When set, every response carries IsValid=false — models a resolver that
    /// could not answer at all, which must surface as Indeterminate rather than Bogus.
    /// </summary>
    public Boolean Unreachable { get; init; }


    /// <summary>Register the answer for one owner name and type. Returns this, for chaining.</summary>
    public StubDnsClient Answer(String                            Name,
                                DNSResourceRecordTypes            Type,
                                params IDNSResourceRecord[]       Records)
    {

        table[(Key(Name), Type)] = [.. Records];

        return this;

    }


    private static String Key(String name)
        => name.TrimEnd('.').ToLowerInvariant();


    private DNSInfo Build(String                               Name,
                          IEnumerable<DNSResourceRecordTypes>  Types)
    {

        var answers = new List<IDNSResourceRecord>();

        foreach (var type in Types)
        {

            Queries.Add((Key(Name), type));

            if (table.TryGetValue((Key(Name), type), out var records))
                answers.AddRange(records);

        }

        return new DNSInfo(
                   origin,
                   0,
                   true,                       // authoritative
                   false,                      // not truncated
                   true,                       // recursion desired
                   false,                      // recursion available
                   DNSResponseCodes.NoError,
                   answers,
                   [],
                   [],
                   !Unreachable,               // IsValid
                   false,                      // IsTimeout
                   TimeSpan.FromSeconds(5),
                   TimeSpan.Zero
               );

    }


    public Task<DNSInfo> Query(DomainName                           DomainName,
                               IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                               TimeSpan?                            Timeout            = null,
                               Boolean?                             RecursionDesired   = true,
                               Boolean?                             ForceUpdate        = false,
                               CancellationToken                    CancellationToken  = default)

        => Task.FromResult(Build(DomainName.FullName, ResourceRecordTypes));


    public Task<DNSInfo> Query(DNSServiceName                       DNSServiceName,
                               IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                               TimeSpan?                            Timeout            = null,
                               Boolean?                             RecursionDesired   = true,
                               Boolean?                             ForceUpdate        = false,
                               CancellationToken                    CancellationToken  = default)

        => Task.FromResult(Build(DNSServiceName.FullName, ResourceRecordTypes));


    public void Dispose()
    { }

    public ValueTask DisposeAsync()
        => ValueTask.CompletedTask;

    public override String ToString()
        => $"stub DNS client ({table.Count} canned RRsets)";

}
