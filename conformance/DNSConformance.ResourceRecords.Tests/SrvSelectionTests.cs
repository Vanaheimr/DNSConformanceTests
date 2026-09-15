using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 2782's server selection: which target a client picks, and how often.
/// </summary>
/// <remarks>
/// <para>
/// Asserting a random distribution is a good way to write a test that fails one
/// morning for no reason, so every bound below sits about seven standard
/// deviations from its expected value — far enough that a correct
/// implementation will not trip it in the lifetime of this suite, and near
/// enough that a defect is caught by a mile.
/// </para>
/// <para>
/// The temptation was to skip the bound on the weight-0 case entirely, since
/// the defect there was <i>never</i> against an expectation of about one draw
/// in fifty, and "greater than zero" says that plainly. A mutation showed why
/// that is not enough: stop putting weight-0 records first and the zero still
/// lands first in a third of the shuffles, so it is still reached — about a
/// third as often. Three times too rare is invisible to a test that only asks
/// whether something ever happens.
/// </para>
/// <para>
/// The seedless <c>Random.Shared</c> is what the implementation uses, so these
/// are statistical rather than reproducible. The alternative — injecting a seed
/// — would make the test exact and would stop testing the thing that matters,
/// which is the behaviour of the code as it actually runs.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "2782")]
public class SrvSelectionTests
{

    #region Data

    private const Int32 Draws = 20000;

    private static DNSSRVEndpoint Endpoint(String Target, UInt16 Priority, UInt16 Weight, Boolean Healthy = true)
        => new (Target, Priority, Weight, IPPort.Parse(443), TimeSpan.FromHours(1), null, Healthy);

    /// <summary>
    /// How often each target is chosen out of <see cref="Draws"/>.
    /// </summary>
    private static Dictionary<String, Int32> Distribution(params DNSSRVEndpoint[] Endpoints)
    {

        var manager = new DNSSRVManager();
        manager.AddOrUpdate("_probe._tcp.example.", Endpoints);

        var counts = Endpoints.ToDictionary(endpoint => endpoint.Target, _ => 0);

        for (var i = 0; i < Draws; i++)
        {

            var chosen = manager.SelectEndpoint("_probe._tcp.example.");

            if (chosen is not null)
                counts[chosen.Target]++;

        }

        return counts;

    }

    #endregion

    #region A_Weight_Of_Zero_Is_Rare_And_Not_Impossible()

    [Test]
    [Property("RFC", "2782")]
    public void A_Weight_Of_Zero_Is_Rare_And_Not_Impossible()
    {

        // "In the presence of records containing weights greater than 0, records
        // with weight 0 should have a very small chance of being selected."
        //
        // It had none. The obvious way to write a weighted pick — subtract each
        // weight and compare with a strict less-than — makes a zero unreachable,
        // because nothing is ever less than zero. Measured over 20,000 draws
        // before the fix: 0.
        //
        // RFC 2782 gets the small chance from three things together: weight-0
        // records first, a random number drawn inclusively from 0 to the sum, and
        // "greater than or equal to". Only a draw of exactly zero reaches a
        // zero-weight record — one outcome in 51 here.
        var counts = Distribution(
                         Endpoint("zero",  10,  0),
                         Endpoint("ten",   10, 10),
                         Endpoint("forty", 10, 40)
                     );

        Assert.Multiple(() => {

            Assert.That(counts["zero"], Is.GreaterThan(0),
                        "a weight-0 target must be reachable at all — this is the finding");

            // The band is narrow enough to be worth something and far enough
            // from the edges to be safe. A weight-0 record is reached only by a
            // draw of exactly zero, one outcome in sum + 1 = 51, so about 392 of
            // 20,000 — binomial, with a standard deviation near 20. These bounds
            // are seven deviations out: a correct implementation will not trip
            // them in the lifetime of this suite.
            //
            // Wide bounds were not enough. A mutation that stops putting
            // weight-0 records first survived "greater than zero": unsorted, the
            // zero still lands first in a third of the shuffles and is still
            // reachable then, giving about 131 instead of 392. Three times too
            // rare, and invisible to a test that only asked whether it ever
            // happened.
            Assert.That(counts["zero"], Is.InRange(250, 550),
                        $"a weight-0 target should be reached about {Draws / 51} times in {Draws}, " +
                        $"and was reached {counts["zero"]}");

            Assert.That(counts["forty"], Is.GreaterThan(counts["ten"]),
                        "and the weights still order the rest");

        });

    }

    #endregion

    #region All_Weights_Zero_Still_Spreads()

    [Test]
    [Property("RFC", "2782")]
    public void All_Weights_Zero_Still_Spreads()
    {

        // "Domain administrators SHOULD use Weight 0 when there isn't any server
        // selection to do" — which is the case where spreading matters most and
        // where the old code did none: every one of 20,000 draws went to the same
        // target, whichever happened to be last in the list.
        //
        // RFC 2782 permits "any order" here, so this is not a MUST. It is what
        // the recommendation is for: three equal targets that never share the
        // load are three targets doing the work of one.
        var counts = Distribution(
                         Endpoint("alpha", 10, 0),
                         Endpoint("beta",  10, 0),
                         Endpoint("gamma", 10, 0)
                     );

        Assert.Multiple(() => {

            foreach (var target in new[] { "alpha", "beta", "gamma" })
                Assert.That(counts[target], Is.GreaterThan(Draws / 10),
                            $"{target} got {counts[target]} of {Draws} — equal weights have to share");

        });

    }

    #endregion

    #region Weights_Set_The_Proportions()

    [Test]
    [Property("RFC", "2782")]
    public void Weights_Set_The_Proportions()
    {

        // "Larger weights SHOULD be given a proportionately higher probability of
        // being selected." The control: this part was already right, and a fix
        // for the two cases above must not buy them by breaking this one.
        var counts = Distribution(
                         Endpoint("one",   10, 10),
                         Endpoint("two",   10, 20),
                         Endpoint("three", 10, 70)
                     );

        Assert.Multiple(() => {

            Assert.That(counts["one"],   Is.InRange(Draws * 5  / 100, Draws * 16 / 100));
            Assert.That(counts["two"],   Is.InRange(Draws * 13 / 100, Draws * 28 / 100));
            Assert.That(counts["three"], Is.InRange(Draws * 60 / 100, Draws * 80 / 100));

        });

    }

    #endregion

    #region The_Lowest_Priority_Wins()

    [Test]
    [Property("RFC", "2782")]
    public void The_Lowest_Priority_Wins()
    {

        // "A client MUST attempt to contact the target host with the
        // lowest-numbered priority it can reach."
        var counts = Distribution(
                         Endpoint("primary",  10, 10),
                         Endpoint("backup",   20, 10)
                     );

        Assert.Multiple(() => {
            Assert.That(counts["primary"], Is.EqualTo(Draws));
            Assert.That(counts["backup"],  Is.Zero, "a higher priority number is a fallback, not a peer");
        });

    }

    #endregion

    #region An_Unreachable_Priority_Is_Not_The_End_Of_The_List()

    [Test]
    [Property("RFC", "2782")]
    public void An_Unreachable_Priority_Is_Not_The_End_Of_The_List()
    {

        // The other half of the same sentence: "the lowest-numbered priority
        // *it can reach*". When nothing at the lowest priority is reachable, the
        // client moves up — it does not report that there is nothing.
        //
        // The old code took the lowest priority and returned null if none of its
        // targets were healthy, which hides every remaining target from a caller
        // that has no other way to learn they exist.
        var counts = Distribution(
                         Endpoint("primary", 10, 10, Healthy: false),
                         Endpoint("backup",  20, 10)
                     );

        Assert.Multiple(() => {
            Assert.That(counts["backup"],  Is.EqualTo(Draws), "the reachable priority has to be used");
            Assert.That(counts["primary"], Is.Zero);
        });

    }

    #endregion

    #region Nothing_Reachable_Is_Still_Nothing()

    [Test]
    public void Nothing_Reachable_Is_Still_Nothing()
    {

        // The bound on the rule above: moving up the priorities must not turn
        // into answering with a target that was marked unreachable.
        var manager = new DNSSRVManager();

        manager.AddOrUpdate("_probe._tcp.example.", [
            Endpoint("primary", 10, 10, Healthy: false),
            Endpoint("backup",  20, 10, Healthy: false)
        ]);

        Assert.That(manager.SelectEndpoint("_probe._tcp.example."), Is.Null);

    }

    #endregion

}
