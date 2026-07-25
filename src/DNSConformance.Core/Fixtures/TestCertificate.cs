using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DNSConformance.Core.Fixtures;

/// <summary>Self-signed server certificates for DoT test listeners.</summary>
public static class TestCertificate
{

    /// <summary>
    /// CN=localhost RSA-2048 server certificate with SANs for localhost and
    /// 127.0.0.1, valid for 7 days, exportable private key.
    /// </summary>
    public static X509Certificate2 CreateServerCertificate(String commonName = "localhost")
    {

        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest(
                          $"CN={commonName}",
                          rsa,
                          HashAlgorithmName.SHA256,
                          RSASignaturePadding.Pkcs1
                      );

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false)
        );

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false
            )
        );

        // id-kp-serverAuth
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false)
        );

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());

        var certificate = request.CreateSelfSigned(
                              DateTimeOffset.UtcNow.AddMinutes(-5),
                              DateTimeOffset.UtcNow.AddDays(7)
                          );

        return X509CertificateLoader.LoadPkcs12(
                   certificate.Export(X509ContentType.Pfx),
                   null,
                   X509KeyStorageFlags.Exportable
               );

    }

}
