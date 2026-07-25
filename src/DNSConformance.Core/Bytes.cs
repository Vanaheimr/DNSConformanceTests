using System.Text;

namespace DNSConformance.Core;

/// <summary>Hex/byte utilities with readable failure output.</summary>
public static class Bytes
{

    /// <summary>Parse hex, ignoring whitespace, line breaks and '0x' prefixes — friendly to RFC excerpt formatting.</summary>
    public static Byte[] FromHex(String hex)
    {

        var clean = new StringBuilder(hex.Length);

        for (var i = 0; i < hex.Length; i++)
        {

            var c = hex[i];

            if (Char.IsWhiteSpace(c) || c is '-' or ':')
                continue;

            if (c == '0' && i + 1 < hex.Length && (hex[i + 1] == 'x' || hex[i + 1] == 'X'))
            {
                i++;
                continue;
            }

            clean.Append(c);

        }

        return Convert.FromHexString(clean.ToString());

    }

    public static String ToHex(ReadOnlySpan<Byte> bytes)
        => Convert.ToHexStringLower(bytes);


    /// <summary>Classic offset/hex/ASCII dump.</summary>
    public static String Dump(ReadOnlySpan<Byte> data)
    {

        var sb = new StringBuilder();

        for (var offset = 0; offset < data.Length; offset += 16)
        {

            sb.Append($"{offset:x4}  ");

            for (var i = 0; i < 16; i++)
            {

                sb.Append(offset + i < data.Length
                              ? $"{data[offset + i]:x2} "
                              : "   ");

                if (i == 7)
                    sb.Append(' ');

            }

            sb.Append(' ');

            for (var i = 0; i < 16 && offset + i < data.Length; i++)
            {
                var b = data[offset + i];
                sb.Append(b is >= 0x20 and <= 0x7E ? (Char) b : '.');
            }

            sb.AppendLine();

        }

        return sb.ToString();

    }


    /// <summary>Human-readable first-difference report for byte comparisons.</summary>
    public static String Diff(Byte[] expected, Byte[] actual)
    {

        if (expected.SequenceEqual(actual))
            return "byte-identical";

        var firstDiff = -1;
        var max       = Math.Min(expected.Length, actual.Length);

        for (var i = 0; i < max; i++)
        {
            if (expected[i] != actual[i])
            {
                firstDiff = i;
                break;
            }
        }

        if (firstDiff < 0)
            firstDiff = max;

        var sb = new StringBuilder();

        sb.AppendLine($"first difference at offset {firstDiff} (0x{firstDiff:x4}); expected {expected.Length} bytes, actual {actual.Length} bytes");
        sb.AppendLine("--- expected ---");
        sb.Append(Dump(expected));
        sb.AppendLine("--- actual ---");
        sb.Append(Dump(actual));

        return sb.ToString();

    }

}
