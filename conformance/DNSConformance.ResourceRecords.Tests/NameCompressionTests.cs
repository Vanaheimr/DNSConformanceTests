using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// Where a name may not become a pointer.
///
/// RFC 1035 §4.1.4 lets a domain name be replaced by a two-octet pointer to an
/// earlier one in the same message, and RFC 3597 §4 draws the line: a name
/// inside the RDATA of a type defined after RFC 1035 must be written out, because
/// a receiver that cannot parse the type cannot find the name to expand it.
///
/// The same rule holds, for a different reason, wherever RDATA is lifted out of
/// the message it was written in. A pointer means "so many octets from the start
/// of this message"; carried somewhere else it points at whatever happens to be
/// there. Every one of those places says <c>UseCompression: false</c>, and the
/// sweep reported each of them as changeable without a test noticing.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §4.1.4, 3597 §4")]
public class NameCompressionTests
{

    #region Data

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(3600);

    /// <summary>Does this run of octets contain a compression pointer?</summary>
    private static Boolean HasPointer(Byte[] Octets)
    {
        for (var i = 0; i < Octets.Length; i++)
            if ((Octets[i] & 0xC0) == 0xC0)
                return true;
        return false;
    }

    #endregion


    #region A name lifted out of its message (RFC 1035 §4.1.4)

    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void An_Owner_Name_Can_Be_Rewritten_Without_Taking_The_Rdata_With_It()
    {

        // Rewriting an owner name means serializing the record, dropping the old
        // name and putting a new one in front of the rest. A pointer anywhere in
        // that "rest" counts from the start of a message that no longer exists —
        // and the one name most likely to be pointed at is the owner, because it
        // is the first thing written. An NS whose target is its own owner is that
        // case exactly.
        var self = ADNSResourceRecord.ParseZoneFileString("zone.example. 3600 IN NS zone.example.");

        var moved = ADNSResourceRecord.CloneWithOwner(self, DNSServiceName.Parse("other.example."));

        Assert.Multiple(() => {
            Assert.That(moved.DomainName.FullName,      Is.EqualTo("other.example."));
            Assert.That((moved as NS)!.NameServer.FullName, Is.EqualTo("zone.example."),
                        "the target is where it was; only the owner moved");
        });

    }

    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Rewritten_Record_Carries_No_Pointer_At_All()
    {

        var self   = ADNSResourceRecord.ParseZoneFileString("zone.example. 3600 IN NS zone.example.");
        var moved  = ADNSResourceRecord.CloneWithOwner(self, DNSServiceName.Parse("other.example."));

        var stream = new MemoryStream();
        moved.Serialize(stream, UseCompression: false, CompressionOffsets: []);

        Assert.That(HasPointer(stream.ToArray()), Is.False,
                    "a record that may be moved again has to be readable on its own");

    }

    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void Rdata_Lifted_Out_Of_A_Message_Carries_No_Pointer()
    {

        // RDataOf serializes a record and hands back the RDATA alone, for a
        // caller that will put it into a different message. RFC 1035 §4.1.4
        // measures a pointer "from the start of the message", so RDATA with a
        // pointer in it is RDATA that only means something where it was written.
        //
        // The owner name records every one of its suffixes, so an NS under its
        // own zone is the case a compressing writer would seize on: the target
        // is already in the table, ten octets into the owner.
        var ns    = ADNSResourceRecord.ParseZoneFileString("sub.zone.example. 3600 IN NS zone.example.");
        var rdata = ADNSResourceRecord.RDataOf(ns);

        Assert.Multiple(() => {

            Assert.That(HasPointer(rdata), Is.False,
                        "the target is written out, because there is no message left to point into");

            Assert.That(rdata.Length, Is.EqualTo(14),
                        "4 zone 7 example 0");

        });

    }

    #endregion


    #region A name inside RDATA that postdates RFC 1035 (RFC 3597 §4)

    [Test]
    [Property("RFC", "3597 §4")]
    public void An_Rp_Writes_Both_Of_Its_Names_Out_In_Full()
    {

        // RFC 3597 §4: "receiving ... MUST NOT compress domain names embedded in
        // the RDATA of types that are class-specific or not well-known." RP is
        // RFC 1183 and not on RFC 1035's list, so neither of its two names may
        // become a pointer — not even when the message has already written that
        // very name and a compressing writer would like to.
        //
        // Both names here are the owner, so a writer allowed to compress would
        // find each of them in the table it just filled in.
        var rp = ADNSResourceRecord.ParseZoneFileString(
                     "same.example. 3600 IN RP same.example. same.example.");

        var stream   = new MemoryStream();
        var offsets  = new Dictionary<String, Int32>();

        rp.Serialize(stream, UseCompression: true, CompressionOffsets: offsets);

        var octets = stream.ToArray();

        // Walk the owner name rather than counting it here, then step over TYPE,
        // CLASS, TTL and RDLENGTH.
        var offset = 0;
        while (octets[offset] != 0)
            offset += 1 + octets[offset];
        offset += 1 + 2 + 2 + 4 + 2;

        var rdata = octets[offset..];

        Assert.That(HasPointer(rdata), Is.False,
                    "an RP's mailbox and TXT names are written out, whatever is already in the table");

        Assert.That(rdata.Length, Is.EqualTo(28),
                    "two names of fourteen octets each: 4 same 7 example 0");

    }

    #endregion

}
