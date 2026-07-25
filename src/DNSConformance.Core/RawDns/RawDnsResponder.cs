namespace DNSConformance.Core.RawDns;

/// <summary>
/// Builds RawDns responses that echo a received query — the standard tool for
/// scripted-server test responders.
/// </summary>
public static class RawDnsResponder
{

    public const UInt16 DefaultFlags = RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA;


    /// <summary>
    /// Build a response for the given query: same ID, the question section
    /// copied byte-identically, the given answers appended.
    /// </summary>
    public static Byte[] Answer(Byte[]                                                        request,
                                params (String Name, UInt16 Type, UInt32 Ttl, Byte[] Rdata)[]  answers)

        => Build(request, DefaultFlags, answers);


    /// <summary>An empty NOERROR response with TC=1 — provokes RFC 7766 TCP fallback.</summary>
    public static Byte[] Truncated(Byte[] request)
        => Build(request, DefaultFlags | RawDnsFlags.TC);


    /// <summary>An empty response with the given RCODE.</summary>
    public static Byte[] Rcode(Byte[] request, Int32 rcode)
        => Build(request, (UInt16) (DefaultFlags | RawDnsFlags.RCode(rcode)));


    /// <summary>Response builder with full flag control. The question section is echoed byte-identically.</summary>
    public static Byte[] Build(Byte[]                                                        request,
                               UInt16                                                        flags,
                               params (String Name, UInt16 Type, UInt32 Ttl, Byte[] Rdata)[]  answers)
    {

        var query          = RawDnsReader.Parse(request, RawDnsReaderOptions.Lenient);

        if (query.Questions.Count == 0)
            return new RawDnsWriter()
                       .Header(query.Id, flags, 0, 0, 0, 0)
                       .ToArray();

        var question       = query.Questions[0];
        var questionBytes  = request[12..(12 + question.Name.WireLength + 4)];

        var writer         = new RawDnsWriter()
                                 .Header(query.Id, flags, 1, (UInt16) answers.Length, 0, 0)
                                 .Bytes(questionBytes);

        foreach (var (name, type, ttl, rdata) in answers)
            writer.RR(name, type, RawDnsClass.IN, ttl, rdata);

        return writer.ToArray();

    }


    /// <summary>
    /// Build a response with a different transaction ID — for RFC 5452
    /// spoofing-resistance tests.
    /// </summary>
    public static Byte[] WithWrongId(Byte[] response)
    {

        var forged  = (Byte[]) response.Clone();
        forged[0]  ^= 0xFF;
        forged[1]  ^= 0x55;

        return forged;

    }

}
