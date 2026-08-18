using System.Net.Http.Headers;
using System.Text;

namespace DNSConformance.Core;

/// <summary>
/// One RFC 8484 exchange as the probe saw it: everything the specification
/// makes a claim about, kept as it came off the wire.
/// </summary>
/// <param name="Status">The HTTP status code.</param>
/// <param name="MediaType">The response media type, without parameters.</param>
/// <param name="CharSet">The <c>charset</c> parameter, if the server sent one. RFC 8484 §7.1 registers none.</param>
/// <param name="ContentType">The Content-Type field verbatim, for a failure message worth reading.</param>
/// <param name="MaxAge">The freshness lifetime from <c>Cache-Control: max-age</c>, or null when the field named none.</param>
/// <param name="CacheControl">The Cache-Control field verbatim.</param>
/// <param name="Allow">The methods named by an <c>Allow</c> field, which RFC 9110 §10.2.1 requires alongside a 405.</param>
/// <param name="Body">The response body — a DNS message when the status is 200.</param>
public sealed record DoHProbeResult(
    Int32                Status,
    String?              MediaType,
    String?              CharSet,
    String?              ContentType,
    TimeSpan?            MaxAge,
    String?              CacheControl,
    IReadOnlyList<String> Allow,
    Byte[]               Body
);


/// <summary>
/// A raw DNS-over-HTTPS client (RFC 8484) built on <see cref="HttpClient"/>,
/// used to judge a DoH <i>server</i> without involving Hermod's own DoH client.
/// </summary>
/// <remarks>
/// <para>
/// The base64url of §4.1 is spelled out here rather than borrowed from the
/// implementation under test. It is four lines, and those four lines are half
/// of what a GET-mode DoH server is judged on — sharing them with the server
/// would make an agreeing pair look like a conforming one.
/// </para>
/// <para>
/// Certificate validation is disabled: the test certificates are self-signed,
/// and the TLS trust decision is not what these tests measure.
/// </para>
/// </remarks>
public static class RawDoHProbe
{

    #region Base64Url(Bytes)

    /// <summary>
    /// RFC 4648 §5 base64url, unpadded — the encoding RFC 8484 §6 requires of a
    /// GET: "the data payload for this media type MUST be encoded with base64url
    /// [RFC4648] […] Padding characters for base64url MUST NOT be included."
    /// </summary>
    public static String Base64Url(Byte[] Bytes)

        => Convert.ToBase64String(Bytes).
                   TrimEnd('=').
                   Replace('+', '-').
                   Replace('/', '_');

    #endregion

    #region NewHttpClient(Timeout = null)

    /// <summary>
    /// An HTTP client that will talk to a self-signed loopback endpoint.
    /// </summary>
    public static HttpClient NewHttpClient(TimeSpan? Timeout = null)

        => new (
               new HttpClientHandler {
                   ServerCertificateCustomValidationCallback = (_, _, _, _) => true
               }
           ) {
               Timeout = Timeout ?? TimeSpan.FromSeconds(10)
           };

    #endregion


    #region PostAsync(Url, Request, ...)

    /// <summary>
    /// RFC 8484 §4.1: "When using the POST method, the DNS query is included as
    /// the message body of the HTTP request, and the Content-Type request header
    /// field indicates the media type of the message."
    /// </summary>
    /// <param name="Url">The DoH endpoint.</param>
    /// <param name="Request">The DNS message, on the wire format of RFC 1035 §4.1.</param>
    /// <param name="ContentType">What to announce the body as. Null omits the field entirely.</param>
    /// <param name="Accept">An Accept field to send, or null for none.</param>
    /// <param name="HTTPClient">A client to reuse, or null to build and dispose one.</param>
    public static async Task<DoHProbeResult> PostAsync(String       Url,
                                                       Byte[]       Request,
                                                       String?      ContentType   = "application/dns-message",
                                                       String?      Accept        = null,
                                                       HttpClient?  HTTPClient    = null)
    {

        using var content = new ByteArrayContent(Request);

        content.Headers.ContentType = ContentType is null
                                          ? null
                                          : MediaTypeHeaderValue.Parse(ContentType);

        using var message = new HttpRequestMessage(HttpMethod.Post, Url) {
                                Content = content
                            };

        return await SendAsync(message, Accept, HTTPClient);

    }

    #endregion

    #region GetAsync(Url, Request, ...)

    /// <summary>
    /// RFC 8484 §4.1: "When the HTTP method is GET, the single variable 'dns' is
    /// defined as the content of the DNS request […] encoded with base64url."
    /// </summary>
    /// <param name="Url">The DoH endpoint, without a query string.</param>
    /// <param name="Request">The DNS message to encode into the <c>dns</c> variable.</param>
    /// <param name="Accept">An Accept field to send, or null for none.</param>
    /// <param name="HTTPClient">A client to reuse, or null to build and dispose one.</param>
    public static Task<DoHProbeResult> GetAsync(String       Url,
                                                Byte[]       Request,
                                                String?      Accept       = null,
                                                HttpClient?  HTTPClient   = null)

        => SendRawAsync(
               HttpMethod.Get,
               $"{Url}?dns={Base64Url(Request)}",
               Accept,
               HTTPClient
           );

    #endregion

    #region SendRawAsync(Method, Url, ...)

    /// <summary>
    /// Any method against any URL, for the tests that are about what a DoH
    /// server refuses rather than what it answers.
    /// </summary>
    public static async Task<DoHProbeResult> SendRawAsync(HttpMethod   Method,
                                                          String       Url,
                                                          String?      Accept       = null,
                                                          HttpClient?  HTTPClient   = null)
    {

        using var message = new HttpRequestMessage(Method, Url);

        return await SendAsync(message, Accept, HTTPClient);

    }

    #endregion

    #region (private) SendAsync(Message, Accept, HTTPClient)

    private static async Task<DoHProbeResult> SendAsync(HttpRequestMessage  Message,
                                                        String?             Accept,
                                                        HttpClient?         HTTPClient)
    {

        // Added as a raw string rather than through the typed collection: some
        // of these tests send an Accept field that is deliberately awkward, and
        // the typed parser would reject it before the server ever saw it.
        if (Accept is not null)
            Message.Headers.TryAddWithoutValidation("Accept", Accept);

        var http = HTTPClient ?? NewHttpClient();

        try
        {

            using var response = await http.SendAsync(Message);

            var body = await response.Content.ReadAsByteArrayAsync();

            return new DoHProbeResult(
                       Status:        (Int32) response.StatusCode,
                       MediaType:     response.Content.Headers.ContentType?.MediaType,
                       CharSet:       response.Content.Headers.ContentType?.CharSet,
                       ContentType:   response.Content.Headers.ContentType?.ToString(),
                       MaxAge:        response.Headers.CacheControl?.MaxAge,
                       CacheControl:  response.Headers.CacheControl?.ToString(),
                       Allow:         [.. response.Content.Headers.Allow],
                       Body:          body
                   );

        }
        finally
        {
            if (HTTPClient is null)
                http.Dispose();
        }

    }

    #endregion

    #region Describe(Result)

    /// <summary>
    /// A one-line rendering for a failure message.
    /// </summary>
    public static String Describe(DoHProbeResult Result)
    {

        var text = new StringBuilder();

        text.Append($"HTTP {Result.Status}");
        text.Append($", content-type: {Result.ContentType   ?? "(none)"}");
        text.Append($", cache-control: {Result.CacheControl ?? "(none)"}");
        text.Append($", {Result.Body.Length} body octets");

        return text.ToString();

    }

    #endregion

}
