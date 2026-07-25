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


    /// <summary>
    /// A negative answer carrying an SOA in the authority section.
    ///
    /// RFC 2308 §3: a negative answer is only cacheable if the responder says for
    /// how long, and the place it says so is the SOA — specifically
    /// min(SOA.MINIMUM, the SOA record's own TTL). Without it a resolver has no
    /// licence to remember the answer at all.
    /// </summary>
    /// <param name="Rcode">0 for NODATA (RFC 2308 §2.2), 3 for NXDOMAIN (§2.1).</param>
    public static Byte[] Negative(Byte[]  request,
                                  Int32   Rcode,
                                  String  Zone,
                                  UInt32  SoaMinimum  = 3600,
                                  UInt32  SoaTtl      = 3600)
    {

        var query          = RawDnsReader.Parse(request, RawDnsReaderOptions.Lenient);
        var question       = query.Questions[0];
        var questionBytes  = request[12..(12 + question.Name.WireLength + 4)];

        var soa            = RawDnsWriter.Soa(
                                 $"ns1.{Zone}",
                                 $"hostmaster.{Zone}",
                                 Minimum: SoaMinimum
                             );

        return new RawDnsWriter().
                   Header(
                       query.Id,
                       (UInt16) (DefaultFlags | RawDnsFlags.AA | RawDnsFlags.RCode(Rcode)),
                       1, 0, 1, 0
                   ).
                   Bytes(questionBytes).
                   RR(Zone, RawDnsType.SOA, RawDnsClass.IN, SoaTtl, soa).
                   ToArray();

    }


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
    /// A referral: NOERROR, no answers, NS records in the authority section and no
    /// SOA.
    ///
    /// It looks exactly like a NODATA answer from the outside — same RCODE, same
    /// empty answer section — and the SOA is the only thing that tells them apart.
    /// Caching one as the other would record "this type does not exist" for a name
    /// whose data simply lives on another server.
    /// </summary>
    public static Byte[] Referral(Byte[]  request,
                                  String  Zone,
                                  String  NameServer)
    {

        var query          = RawDnsReader.Parse(request, RawDnsReaderOptions.Lenient);
        var question       = query.Questions[0];
        var questionBytes  = request[12..(12 + question.Name.WireLength + 4)];

        return new RawDnsWriter().
                   Header(query.Id, DefaultFlags, 1, 0, 1, 0).
                   Bytes(questionBytes).
                   RR(Zone, RawDnsType.NS, RawDnsClass.IN, 3600, RawDnsWriter.NameBytes(NameServer)).
                   ToArray();

    }


    /// <summary>
    /// Fold the QNAME in the question section to lower case, leaving the rest of
    /// the message untouched. Models the many resolvers that normalize names
    /// internally: RFC 4343 makes the result the same name, so a client must still
    /// accept it as the answer to its differently-cased query.
    /// </summary>
    public static Byte[] WithLowercasedQuestion(Byte[] message)
    {

        var folded  = (Byte[]) message.Clone();
        var offset  = 12;

        while (offset < folded.Length && folded[offset] != 0)
        {

            var length = folded[offset];

            if (length >= 0xC0)   // a compression pointer terminates the name
                break;

            for (var i = offset + 1; i <= offset + length && i < folded.Length; i++)
                if (folded[i] >= (Byte) 'A' && folded[i] <= (Byte) 'Z')
                    folded[i] |= 0x20;

            offset += 1 + length;

        }

        return folded;

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
