using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// An <see cref="IDNSClient"/> that answers from a canned table instead of a
/// socket, so <see cref="DNSSECValidator.ValidateAsync"/> can be driven through
/// every RFC 4035 §4.3 outcome offline and deterministically.
///
/// It resolves nothing on its own: whatever a test does not register is answered
/// as an empty NOERROR. That is not how a validator learns that a zone publishes
/// no DS — RFC 4035 §5.2 wants that proven by the parent's signed NSEC or NSEC3
/// records, which a test registers with <see cref="Authority"/> — and since
/// finding 73 an empty answer alone is no proof of anything.
/// </summary>
public sealed class StubDnsClient : IDNSClient
{

    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), List<IDNSResourceRecord>> table       = [];
    private readonly Dictionary<(String Name, DNSResourceRecordTypes Type), List<IDNSResourceRecord>> authorities = [];

    private static readonly DNSServerConfig origin = new(IPv4Address.Localhost, IPPort.DNS);


    /// <summary>
    /// Every query this client received, in order — for asserting what a validator asked for.
    /// </summary>
    public List<(String Name, DNSResourceRecordTypes Type)> Queries { get; } = [];

    /// <summary>
    /// When set, every response carries IsValid=false — models a resolver that
    /// could not answer at all, which must surface as Indeterminate rather than Bogus.
    /// </summary>
    public Boolean Unreachable { get; init; }

    /// <summary>
    /// When set, every query comes back as a faulted task instead of a response
    /// — a transport that failed outright, which is a different thing from a
    /// resolver that answered "I do not know".
    /// </summary>
    public Boolean Throws { get; init; }


    /// <summary>
    /// Register the answer for one owner name and type. Returns this, for chaining.
    /// </summary>
    public StubDnsClient Answer(String                            Name,
                                DNSResourceRecordTypes            Type,
                                params IDNSResourceRecord[]       Records)
    {

        table[(Key(Name), Type)] = [.. Records];

        return this;

    }


    /// <summary>
    /// Register the authority section for one owner name and type — the SOA and
    /// the signed NSEC or NSEC3 records of a negative answer. Returns this, for
    /// chaining.
    /// </summary>
    public StubDnsClient Authority(String                            Name,
                                   DNSResourceRecordTypes            Type,
                                   params IDNSResourceRecord[]       Records)
    {

        authorities[(Key(Name), Type)] = [.. Records];

        return this;

    }


    private static String Key(String name)
        => name.TrimEnd('.').ToLowerInvariant();


    private DNSInfo Build(String                               Name,
                          IEnumerable<DNSResourceRecordTypes>  Types)
    {

        var answers     = new List<IDNSResourceRecord>();
        var authority   = new List<IDNSResourceRecord>();

        foreach (var type in Types)
        {

            Queries.Add((Key(Name), type));

            if (table.TryGetValue((Key(Name), type), out var records))
                answers.AddRange(records);

            if (authorities.TryGetValue((Key(Name), type), out var denial))
                authority.AddRange(denial);

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
                   authority,
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

        => Throws
               ? Task.FromException<DNSInfo>(new IOException("the stub was told the transport is broken"))
               : Task.FromResult(Build(DomainName.FullName, ResourceRecordTypes));


    public Task<DNSInfo> Query(DNSServiceName                       DNSServiceName,
                               IEnumerable<DNSResourceRecordTypes>  ResourceRecordTypes,
                               TimeSpan?                            Timeout            = null,
                               Boolean?                             RecursionDesired   = true,
                               Boolean?                             ForceUpdate        = false,
                               CancellationToken                    CancellationToken  = default)

        => Throws
               ? Task.FromException<DNSInfo>(new IOException("the stub was told the transport is broken"))
               : Task.FromResult(Build(DNSServiceName.FullName, ResourceRecordTypes));


    public void Dispose()
    { }

    public ValueTask DisposeAsync()
        => ValueTask.CompletedTask;

    public override String ToString()
        => $"stub DNS client ({table.Count} canned RRsets, {authorities.Count} authority sections)";

}
