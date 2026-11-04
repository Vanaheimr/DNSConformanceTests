namespace DNSConformance.Multicast.Tests;

/// <summary>
/// A clock whose timers fire only when the test moves it. A querier that waits on this
/// clock sends when the test runs its wait out, and the time it sends at is this
/// clock's, which nothing running beside the test can stretch.
/// </summary>
/// <remarks>
/// <para>
/// The tests that measured §5.2's intervals on the wall clock failed now and then:
/// once with a first query 191 ms after the browse began, once with a first interval
/// of 1120 ms, which the next comparison doubled. Both were the machine, not the
/// querier, and no tolerance tells the two apart. On this clock an interval is exactly
/// what the querier asked for, and is compared with nothing added.
/// </para>
/// <para>
/// One-shot timers are a querier's waits: the delay before a browse, the interval
/// before the next query, the time left before a lookup's deadline. Periodic timers,
/// the cache sweep and the browser's maintenance tick, fire as the clock passes them.
/// </para>
/// <para>
/// Hermod ships a FakeTimeProvider in its own test project. Borrowing it would let
/// Hermod supply both the implementation and the instrument that judges it.
/// </para>
/// </remarks>
internal sealed class ManualClock : TimeProvider
{

    private sealed class ManualTimer(ManualClock Clock, TimerCallback Callback, Object? State) : ITimer
    {

        public DateTimeOffset?  Due     { get; set; }
        public TimeSpan         Period  { get; set; }

        public Boolean IsOneShot
            => Period <= TimeSpan.Zero;

        public void Fire()
            => Callback(State);

        public Boolean Change(TimeSpan DueTime, TimeSpan Period)
        {
            lock (Clock.sync)
            {
                Due          = DueTime == Timeout.InfiniteTimeSpan ? null : Clock.now + DueTime;
                this.Period  = Period  == Timeout.InfiniteTimeSpan ? TimeSpan.Zero : Period;
            }
            return true;
        }

        public void Dispose()
        {
            lock (Clock.sync)
            {
                Due = null;
                Clock.timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

    }


    private static readonly DateTimeOffset  Start   = new (2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly Object                 sync    = new();
    private readonly List<ManualTimer>      timers  = [];
    private DateTimeOffset                  now     = Start;


    public override DateTimeOffset GetUtcNow()
    {
        lock (sync)
            return now;
    }

    /// <summary>How far the clock has been moved since it was made.</summary>
    public TimeSpan Elapsed
        => GetUtcNow() - Start;

    public override ITimer CreateTimer(TimerCallback  Callback,
                                       Object?        State,
                                       TimeSpan       DueTime,
                                       TimeSpan       Period)
    {

        var timer = new ManualTimer(this, Callback, State);

        lock (sync)
            timers.Add(timer);

        timer.Change(DueTime, Period);

        return timer;

    }


    /// <summary>
    /// When the earliest wait now pending ends, as time elapsed on this clock. The wait
    /// is looked for until one is pending, or until <paramref name="Until"/> completes,
    /// which yields null: a lookup that has given up waits for nothing more.
    /// </summary>
    /// <remarks>
    /// A querier sends, and only then starts its next wait. So once that wait is
    /// pending, the query before it is out, and was sent at the time this clock showed.
    /// </remarks>
    public async Task<TimeSpan?> NextWait(Task?  Until                = null,
                                          Int32  TimeoutMilliseconds  = 5000)
    {

        var deadline = DateTime.UtcNow.AddMilliseconds(TimeoutMilliseconds);

        while (DateTime.UtcNow < deadline)
        {

            lock (sync)
            {
                var due = timers.Where(timer => timer.IsOneShot && timer.Due.HasValue).
                                 Select(timer => timer.Due!.Value).
                                 DefaultIfEmpty(DateTimeOffset.MaxValue).
                                 Min();

                if (due != DateTimeOffset.MaxValue)
                    return due - Start;
            }

            if (Until?.IsCompleted == true)
                return null;

            await Task.Delay(5);

        }

        throw new TimeoutException($"no wait was pending on the clock after {TimeoutMilliseconds} ms of real time");

    }

    /// <summary>
    /// Run the earliest wait out, once one is pending, and say when it ended.
    /// </summary>
    public async Task<TimeSpan> RunOutNextWait()
    {

        var due = (await NextWait())!.Value;

        AdvanceTo(due);

        return due;

    }

    /// <summary>
    /// Move the clock to the given time elapsed, firing every timer due on the way, each
    /// at the time it is due. A timer started by one that fires is fired too, if it is
    /// due by then.
    /// </summary>
    public void AdvanceTo(TimeSpan Elapsed)
    {

        var target = Start + Elapsed;

        while (true)
        {

            ManualTimer? next;

            lock (sync)
            {

                next = timers.Where(timer => timer.Due.HasValue && timer.Due.Value <= target).
                              MinBy(timer => timer.Due!.Value);

                if (next is null)
                {
                    if (target > now)
                        now = target;
                    return;
                }

                now       = next.Due!.Value;
                next.Due  = next.IsOneShot ? null : now + next.Period;

            }

            next.Fire();

        }

    }

}
