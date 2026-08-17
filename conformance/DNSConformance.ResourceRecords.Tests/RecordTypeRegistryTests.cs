using System.Reflection;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// The contract that Hermod's resource-record registry depends on but no
/// compiler enforces.
///
/// <para>
/// <c>DNSInfo</c>'s static constructor sweeps the assembly for concrete
/// <c>ADNSResourceRecord</c> subclasses and indexes each one by its
/// <c>TypeId</c> constant and one of exactly two stream constructors —
/// <c>(DNSServiceName, Stream)</c> or <c>(DomainName, Stream)</c>.
/// <c>ReadResourceRecord</c> then dispatches every record it reads off the wire
/// through that index.
/// </para>
///
/// <para>
/// A type that breaks the contract fails in one of two ways, neither of them at
/// build time: a missing or mistyped <c>TypeId</c> throws out of the static
/// constructor, which surfaces as a <c>TypeInitializationException</c> and takes
/// the entire DNS stack down on first use; a missing constructor is worse,
/// because it is silent — the type registers in neither lookup, and every record
/// of that type is dropped from every response with nothing but a debug log to
/// say so.
/// </para>
///
/// <para>
/// These tests deliberately carry no <c>[Property("RFC", …)]</c>. They assert an
/// implementation contract rather than a specification requirement, and must not
/// count towards the suite's RFC coverage.
/// </para>
/// </summary>
[TestFixture]
public class RecordTypeRegistryTests
{

    #region (private static) RegisteredRecordTypes

    /// <summary>
    /// The types the registry sweeps, enumerated exactly as its static
    /// constructor does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OPT is absent by design: it is a pseudo-RR that implements
    /// <c>IDNSPseudoResourceRecord</c> instead of extending
    /// <c>ADNSResourceRecord</c>, so <c>ReadResourceRecord</c> constructs it
    /// explicitly before consulting the registry. That call site is an ordinary
    /// compile-time reference and needs no test to defend it.
    /// </para>
    /// <para>
    /// <c>UnknownRecord</c> is absent for the opposite reason: it answers for
    /// every type code that has no class, so it cannot be indexed under one. It
    /// carries its type as a constructor argument rather than a <c>TypeId</c>
    /// constant, and the registry's own sweep skips it by name. The exclusion is
    /// not taken on trust — <see cref="The_Fallback_Is_Not_In_The_Index"/>
    /// measures it.
    /// </para>
    /// </remarks>
    private static IEnumerable<Type> RegisteredRecordTypes()

        => typeof(ADNSResourceRecord).
               Assembly.GetTypes().
               Where(type => type.IsClass &&
                            !type.IsAbstract &&
                             type.IsSubclassOf(typeof(ADNSResourceRecord)) &&
                             type != typeof(UnknownRecord)).
               OrderBy(type => type.Name);

    #endregion


    #region The_Fallback_Is_Not_In_The_Index()

    [Test]
    public void The_Fallback_Is_Not_In_The_Index()
    {

        // The fixture above excludes UnknownRecord from every "for all
        // registered types" claim. That exclusion is only honest while the
        // registry excludes it too — if the sweep ever indexed it, it would sit
        // under some arbitrary type code and answer for records that have a real
        // parser, and the exclusion here would be hiding it rather than
        // describing it.
        var known = ReadOneRecord(RawDnsType.TXT, [ 5, (Byte) 'h', (Byte) 'e', (Byte) 'l', (Byte) 'l', (Byte) 'o' ]);

        Assert.That(known, Is.Not.InstanceOf<UnknownRecord>(),
                    "a TXT record came back as the unknown-type fallback, so the fallback has taken " +
                    "a place in the registry that belongs to a real parser.");

        Assert.That(known?.Type, Is.EqualTo(DNSResourceRecordTypes.TXT));

    }

    #endregion

    #region (private static) ReadOneRecord(Type, Rdata)

    /// <summary>
    /// Read a single record of the given type off a crafted wire image.
    /// </summary>
    private static IDNSResourceRecord? ReadOneRecord(UInt16 Type, Byte[] Rdata)
    {

        var wire = new RawDnsWriter().
                       RR("probe.example.", Type, RawDnsClass.IN, 300, Rdata).
                       ToArray();

        return DNSInfo.ReadResourceRecord(new MemoryStream(wire));

    }

    #endregion


    #region The_Sweep_Finds_The_Record_Types()

    [Test]
    public void The_Sweep_Finds_The_Record_Types()
    {

        // A guard on the guards. Every assertion below is a "for all registered
        // types" claim, and all of them pass vacuously if the sweep ever stops
        // finding anything — a renamed base class, a moved assembly.
        Assert.That(RegisteredRecordTypes().Count(), Is.GreaterThan(30),
                    "the registry sweep found almost no record types, which makes every " +
                    "other assertion in this fixture vacuous — has ADNSResourceRecord moved?");

    }

    #endregion

    #region Every_Record_Type_Has_A_TypeId_Constant()

    [Test]
    public void Every_Record_Type_Has_A_TypeId_Constant()
    {

        // DNSInfo's static constructor throws when TypeId is missing or is not a
        // DNSResourceRecordTypes. Thrown from a static constructor, that becomes a
        // TypeInitializationException on the first DNS operation of the process.
        var broken = RegisteredRecordTypes().
                         Where(type => type.GetField("TypeId")?.GetValue(type) is not DNSResourceRecordTypes).
                         Select(type => type.Name).
                         ToArray();

        Assert.That(broken, Is.Empty,
                    $"these record types carry no usable 'TypeId' constant: {String.Join(", ", broken)}. " +
                     "The registry throws on them while initialising, so the first DNS query in the " +
                     "process fails with a TypeInitializationException rather than a parse error.");

    }

    #endregion

    #region Every_Record_Type_Is_Reachable_From_The_Wire()

    [Test]
    public void Every_Record_Type_Is_Reachable_From_The_Wire()
    {

        // These are the only two signatures the registry looks for. A record type
        // with neither is registered in neither lookup, and ReadResourceRecord
        // returns null for it: the record vanishes from the response, silently.
        var unreachable = RegisteredRecordTypes().
                              Where(type => type.GetConstructor([ typeof(DNSServiceName), typeof(Stream) ]) is null &&
                                            type.GetConstructor([ typeof(DomainName),     typeof(Stream) ]) is null).
                              Select(type => type.Name).
                              ToArray();

        Assert.That(unreachable, Is.Empty,
                    $"these record types have neither (DNSServiceName, Stream) nor (DomainName, Stream): " +
                    $"{String.Join(", ", unreachable)}. The registry cannot construct them, so every record " +
                     "of these types is dropped from every response — no exception, no RCODE, just a debug log.");

    }

    #endregion

    #region Record_Type_Ids_Are_Unique()

    [Test]
    public void Record_Type_Ids_Are_Unique()
    {

        // The registry indexes with TryAdd, which keeps the first arrival and
        // discards the rest without complaint. Two types sharing a TypeId
        // therefore leave one of them permanently unreachable — and which one
        // loses depends on Assembly.GetTypes() ordering, so the same build can
        // decide it differently than the last.
        var collisions = RegisteredRecordTypes().
                             Select(type => (Name: type.Name, Id: type.GetField("TypeId")?.GetValue(type))).
                             Where (entry => entry.Id is DNSResourceRecordTypes).
                             GroupBy(entry => (DNSResourceRecordTypes) entry.Id!).
                             Where (group => group.Count() > 1).
                             Select(group => $"{group.Key} ({String.Join(" + ", group.Select(entry => entry.Name))})").
                             ToArray();

        Assert.That(collisions, Is.Empty,
                    $"these TypeIds are claimed by more than one record type: {String.Join("; ", collisions)}. " +
                     "The registry keeps whichever the runtime enumerated first and silently drops the other.");

    }

    #endregion

    #region No_Record_Type_Offers_A_Decoy_Stream_Constructor()

    [Test]
    public void No_Record_Type_Offers_A_Decoy_Stream_Constructor()
    {

        // A bare (Stream) constructor is not a parse path: the registry never
        // looks for that signature, so nothing on the wire can ever reach it.
        // What it does instead is sit next to the real constructor looking just
        // like it — and the family that used to be here read the owner name and
        // TYPE itself while leaving RDLENGTH unread, so half of them consumed the
        // two length octets as RDATA. Whoever writes the next record type by
        // copying an existing one must not find that shape to copy.
        var decoys = RegisteredRecordTypes().
                         Where(type => type.GetConstructor([ typeof(Stream) ]) is not null).
                         Select(type => type.Name).
                         ToArray();

        Assert.That(decoys, Is.Empty,
                    $"these record types expose a bare (Stream) constructor: {String.Join(", ", decoys)}. " +
                     "The registry cannot reach it, so it parses nothing — it only offers a second, " +
                     "unexercised decoding path for the next record type to be modelled on.");

    }

    #endregion

}
