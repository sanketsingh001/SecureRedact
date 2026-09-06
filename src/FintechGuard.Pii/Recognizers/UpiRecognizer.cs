using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Unified Payments Interface (UPI) Virtual Payment Addresses (VPA).
/// Matches common bank/PSP handles (@okhdfcbank, @okaxis, @paytm, @ybl, @upi, @icici, @axl, @ibl, etc.).
/// </summary>
public sealed partial class UpiRecognizer : IPiiRecognizer
{
    public string Name => "Indian_UPI";
    public PiiType PiiType => PiiType.UpiId;

    [GeneratedRegex(@"\b[a-zA-Z0-9.\-_]{2,64}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|axl|upi|icici|hdfcbank|sbi|kotak|barodampay|waaxis|idfcbank)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex UpiPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = UpiPattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.UpiId,
                TypeName = nameof(PiiType.UpiId),
                Confidence = 0.98,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}
