using System.Diagnostics;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSInterop.Multicast.Tests;

/// <summary>
/// Bidirectional interoperability with the host's native dns-sd implementation
/// (Windows DNS-SD/Bonjour, or a compatible dns-sd command on Unix).
/// </summary>
[TestFixture]
[Category(TestCategories.Multicast)]
[NonParallelizable]
public sealed class NativeDnsSdInteropTests
{

    private sealed class DnsSdProcess : IDisposable
    {
        private readonly StringBuilder output = new();
        public Process Process { get; }

        public String Output
        {
            get
            {
                lock (output)
                    return output.ToString();
            }
        }

        public DnsSdProcess(String executable, params String[] arguments)
        {
            var startInfo = new ProcessStartInfo {
                                FileName                = executable,
                                RedirectStandardOutput  = true,
                                RedirectStandardError   = true,
                                UseShellExecute         = false,
                                CreateNoWindow          = true
                            };

            foreach (var argument in arguments)
                startInfo.ArgumentList.Add(argument);

            Process = Process.Start(startInfo)
                          ?? throw new InvalidOperationException($"Could not start {executable}.");

            Process.OutputDataReceived += (_, e) => Append(e.Data);
            Process.ErrorDataReceived  += (_, e) => Append(e.Data);
            Process.BeginOutputReadLine();
            Process.BeginErrorReadLine();
        }

        private void Append(String? line)
        {
            if (line is null)
                return;
            lock (output)
                output.AppendLine(line);
        }

        public void Dispose()
        {
            try
            {
                if (!Process.HasExited)
                    Process.Kill(entireProcessTree: true);
            }
            catch
            { }

            try
            {
                Process.WaitForExit(3000);
            }
            catch
            { }

            Process.Dispose();
        }
    }


    private static String RequireDnsSd()
    {
        var executable = OperatingSystem.IsWindows()
                             ? Path.Combine(Environment.SystemDirectory, "dns-sd.exe")
                             : "dns-sd";

        try
        {
            using var probe = new DnsSdProcess(executable, "-h");
            if (!probe.Process.WaitForExit(5000))
                Assert.Ignore($"'{executable} -h' did not complete; native DNS-SD is unavailable.");
            if (probe.Process.ExitCode != 0)
                Assert.Ignore($"'{executable}' is unavailable: {probe.Output}");
        }
        catch (Exception e) when (e is not SuccessException)
        {
            Assert.Ignore($"No native dns-sd command is available: {e.Message}");
        }

        return executable;
    }


    private static async Task WaitUntil(Func<Boolean> condition,
                                        TimeSpan      timeout,
                                        String        failure)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (condition())
                return;
            await Task.Delay(100);
        }

        Assert.Fail(failure);
    }


    private static UDPMulticastDNSTransport NewTransport()
        => new(
               new UDPMulticastDNSTransportOptions {
                   EnableIPv4  = true,
                   EnableIPv6  = false
               }
           );


    private static IDNSResourceRecord[] ServiceRecords(String instance,
                                                       String host,
                                                       String address,
                                                       UInt16 port)
    {
        var hostName     = DomainName.Parse(host);
        var serviceType  = DNSServiceName.Parse("_hermodtest._tcp.local.");
        var instanceName = DNSServiceName.Parse($"{instance}._hermodtest._tcp.local.");

        return [
            new A  (hostName,     DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  IPv4Address.Parse(address)),
            new SRV(instanceName, DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  0, 0, IPPort.Parse(port), hostName),
            new TXT(instanceName, DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), [ "txtvers=1", "path=/interop" ]),
            new PTR(serviceType,  DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), instanceName)
        ];
    }


    [Test]
    [Property("RFC", "6762")]
    [Property("RFC", "6763 §4, §12")]
    public async Task Native_DnsSd_Browser_Discovers_A_Hermod_Publication()
    {
        var dnsSd     = RequireDnsSd();
        var suffix    = Guid.NewGuid().ToString("N")[..8];
        var instance  = $"Hermod-{suffix}";
        var host      = $"hermod-{suffix}.local.";

        await using var transport = NewTransport();
        await using var responder = new MulticastDNSResponder(transport);

        try
        {
            await responder.StartAsync();
        }
        catch (InvalidOperationException e)
        {
            Assert.Ignore($"No multicast-capable interface: {e.Message}");
        }

        var address = transport.LocalAddresses.OfType<IPv4Address>().FirstOrDefault();
        if (address == default)
            Assert.Ignore("No IPv4 address is available on a multicast-capable interface.");

        using var browser = new DnsSdProcess(dnsSd, "-B", "_hermodtest._tcp", "local.");
        await Task.Delay(500);

        var publication = await responder.PublishAsync(
                                  ServiceRecords(instance, host, address.ToString(), 18053)
                              );

        await WaitUntil(
                  () => browser.Output.Contains(instance, StringComparison.OrdinalIgnoreCase),
                  TimeSpan.FromSeconds(15),
                  $"Native dns-sd did not discover Hermod's '{instance}' publication. Output:{Environment.NewLine}{browser.Output}"
              );

        TestContext.Out.WriteLine(browser.Output);
        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published));
    }


    [Test]
    [Property("RFC", "6762")]
    [Property("RFC", "6763 §4-§6")]
    public async Task Hermod_Browser_Resolves_A_Native_DnsSd_Publication()
    {
        var dnsSd     = RequireDnsSd();
        var suffix    = Guid.NewGuid().ToString("N")[..8];
        var instance  = $"Native-{suffix}";

        using var registration = new DnsSdProcess(
                                     dnsSd,
                                     "-R", instance, "_hermodtest._tcp", "local.", "18054",
                                     "txtvers=1", "path=/native"
                                 );

        await Task.Delay(750);

        if (registration.Process.HasExited)
            Assert.Ignore($"Native dns-sd registration exited early: {registration.Output}");

        await using var transport = NewTransport();
        await using var client    = new MulticastDNSClient(
                                        transport,
                                        new MulticastDNSClientOptions {
                                            QueryTimeout               = TimeSpan.FromSeconds(3),
                                            ResponseGracePeriod        = TimeSpan.FromMilliseconds(150),
                                            RetransmissionInterval     = TimeSpan.FromSeconds(1),
                                            RequestUnicastResponses    = false,
                                            InitialBrowseInterval      = TimeSpan.FromSeconds(1),
                                            BrowseMaintenanceInterval  = TimeSpan.FromMilliseconds(250)
                                        }
                                    );

        try
        {
            await client.StartAsync();
        }
        catch (InvalidOperationException e)
        {
            Assert.Ignore($"No multicast-capable interface: {e.Message}");
        }

        await using var browser = await client.BrowseAsync(
                                             DNSServiceName.Parse("_hermodtest._tcp.local.")
                                         );

        MulticastDNSServiceInstance? discovered = null;

        await WaitUntil(
                  () => {
                      discovered = browser.Instances.FirstOrDefault(
                                       service => service.InstanceName.FullName.StartsWith(
                                                      instance + ".",
                                                      StringComparison.OrdinalIgnoreCase
                                                  )
                                   );
                      return discovered is not null;
                  },
                  TimeSpan.FromSeconds(15),
                  $"Hermod did not resolve native dns-sd's '{instance}' publication. Native output:{Environment.NewLine}{registration.Output}"
              );

        Assert.Multiple(() => {
            Assert.That(discovered!.Port?.ToUInt16(), Is.EqualTo((UInt16) 18054));
            Assert.That(discovered.HostName, Is.Not.Null);
            Assert.That(discovered.TXT?.KeyValues["txtvers"], Is.EqualTo("1"));
            Assert.That(discovered.TXT?.KeyValues["path"],    Is.EqualTo("/native"));
        });
    }

}
