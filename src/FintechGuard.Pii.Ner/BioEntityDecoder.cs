using FintechGuard.Pii.Core;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace FintechGuard.Pii.Ner;

internal readonly record struct OnnxTokenWindowItem(int StartOffset, int EndOffset, bool IsSpecial, bool IsSubword);

/// <summary>
/// Decodes ONNX token-classification logits ([seqLen, numLabels] or [batch, seqLen, numLabels])
/// via numerically stable softmax and BIO/BIOES span reconstruction mapped back to exact UTF-16 character offsets.
/// </summary>
internal static class BioEntityDecoder
{
    public static List<PiiMatch> DecodeWindow(
        string originalText,
        Tensor<float> logits,
        int batchRowIndex,
        ReadOnlySpan<OnnxTokenWindowItem> windowTokens,
        OnnxNerOptions options)
    {
        var results = new List<PiiMatch>();
        int seqLen = windowTokens.Length;
        if (seqLen == 0 || logits.Dimensions.Length < 3)
            return results;

        int numLabels = logits.Dimensions[2];
        int tensorSeqLen = Math.Min(seqLen, logits.Dimensions[1]);

        string? activeEntityType = null;
        int activeStart = -1;
        int activeEnd = -1;
        double probSum = 0.0;
        int probCount = 0;

        for (int t = 0; t < tensorSeqLen; t++)
        {
            var tok = windowTokens[t];
            if (tok.IsSpecial || tok.EndOffset <= tok.StartOffset)
            {
                FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                continue;
            }

            (int bestId, double bestProb) = ArgMaxSoftmax(logits, batchRowIndex, t, numLabels);
            string label = options.IdToLabel.TryGetValue(bestId, out var mapped) ? mapped : "O";

            if (label.Equals("O", StringComparison.OrdinalIgnoreCase))
            {
                // If WordPiece continuation subword of the currently active word is tagged O, keep whole word intact
                if (activeEntityType != null && tok.IsSubword && tok.StartOffset == activeEnd)
                {
                    activeEnd = tok.EndOffset;
                    continue;
                }

                FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                continue;
            }

            ParseBioTag(label, out char prefix, out string entityType);
            if (string.IsNullOrEmpty(entityType))
            {
                FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                continue;
            }

            if (prefix == 'B' || prefix == 'S')
            {
                if (prefix == 'B' &&
                    tok.IsSubword &&
                    activeEntityType != null &&
                    string.Equals(activeEntityType, entityType, StringComparison.OrdinalIgnoreCase) &&
                    tok.StartOffset == activeEnd)
                {
                    if (tok.EndOffset > activeEnd)
                        activeEnd = tok.EndOffset;
                    probSum += bestProb;
                    probCount++;
                    continue;
                }

                FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                int minAllowedOffset = results.Count > 0 ? results[results.Count - 1].Index + results[results.Count - 1].Length : 0;
                activeEntityType = entityType;
                activeStart = SnapStartToWordBoundary(windowTokens, t, minAllowedOffset);
                activeEnd = tok.EndOffset;
                probSum = bestProb;
                probCount = 1;

                if (prefix == 'S')
                {
                    FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                }
            }
            else if (prefix == 'I' || prefix == 'E')
            {
                if (activeEntityType != null && string.Equals(activeEntityType, entityType, StringComparison.OrdinalIgnoreCase))
                {
                    if (tok.EndOffset > activeEnd)
                        activeEnd = tok.EndOffset;
                    probSum += bestProb;
                    probCount++;
                }
                else
                {
                    FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                    int minAllowedOffset = results.Count > 0 ? results[results.Count - 1].Index + results[results.Count - 1].Length : 0;
                    activeEntityType = entityType;
                    activeStart = SnapStartToWordBoundary(windowTokens, t, minAllowedOffset);
                    activeEnd = tok.EndOffset;
                    probSum = bestProb;
                    probCount = 1;
                }

                if (prefix == 'E')
                {
                    FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                }
            }
            else
            {
                // Non-BIO bare label (e.g. "PER"): merge contiguous same-type tokens
                if (activeEntityType != null && string.Equals(activeEntityType, entityType, StringComparison.OrdinalIgnoreCase))
                {
                    if (tok.EndOffset > activeEnd)
                        activeEnd = tok.EndOffset;
                    probSum += bestProb;
                    probCount++;
                }
                else
                {
                    FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
                    int minAllowedOffset = results.Count > 0 ? results[results.Count - 1].Index + results[results.Count - 1].Length : 0;
                    activeEntityType = entityType;
                    activeStart = SnapStartToWordBoundary(windowTokens, t, minAllowedOffset);
                    activeEnd = tok.EndOffset;
                    probSum = bestProb;
                    probCount = 1;
                }
            }
        }

        FlushEntity(originalText, options, ref activeEntityType, ref activeStart, ref activeEnd, ref probSum, ref probCount, results);
        return results;
    }

    public static void MergeWindowMatches(List<PiiMatch> allMatches, List<PiiMatch> destination)
    {
        if (allMatches.Count == 0)
            return;

        allMatches.Sort(static (a, b) =>
        {
            int cmp = a.Index.CompareTo(b.Index);
            return cmp != 0 ? cmp : b.Length.CompareTo(a.Length);
        });

        for (int i = 0; i < allMatches.Count; i++)
        {
            var m = allMatches[i];
            bool overlaps = false;
            for (int j = 0; j < destination.Count; j++)
            {
                var ex = destination[j];
                if (m.Index < ex.Index + ex.Length && m.Index + m.Length > ex.Index)
                {
                    if (m.Confidence > ex.Confidence || (m.Confidence == ex.Confidence && m.Length > ex.Length))
                        destination[j] = m;
                    overlaps = true;
                    break;
                }
            }

            if (!overlaps)
                destination.Add(m);
        }
    }

    private static (int BestId, double BestProb) ArgMaxSoftmax(Tensor<float> logits, int batchIdx, int tokenIdx, int numLabels)
    {
        float maxLogit = float.NegativeInfinity;
        int bestId = 0;

        for (int c = 0; c < numLabels; c++)
        {
            float v = logits[batchIdx, tokenIdx, c];
            if (v > maxLogit)
            {
                maxLogit = v;
                bestId = c;
            }
        }

        double sumExp = 0.0;
        for (int c = 0; c < numLabels; c++)
        {
            sumExp += Math.Exp(logits[batchIdx, tokenIdx, c] - maxLogit);
        }

        double bestProb = sumExp > 0.0 ? 1.0 / sumExp : 0.0;
        return (bestId, bestProb);
    }

    private static void ParseBioTag(string label, out char prefix, out string entityType)
    {
        if (label.Length > 2 && label[1] == '-')
        {
            char p = char.ToUpperInvariant(label[0]);
            if (p == 'B' || p == 'I' || p == 'E' || p == 'S')
            {
                prefix = p;
                entityType = label[2..];
                return;
            }
        }

        prefix = '\0';
        entityType = label;
    }

    private static int SnapStartToWordBoundary(ReadOnlySpan<OnnxTokenWindowItem> windowTokens, int tokenIndex, int minAllowedOffset)
    {
        int start = windowTokens[tokenIndex].StartOffset;
        if (!windowTokens[tokenIndex].IsSubword)
            return start;

        for (int k = tokenIndex - 1; k >= 0; k--)
        {
            var prev = windowTokens[k];
            if (prev.IsSpecial || prev.EndOffset != start || prev.StartOffset < minAllowedOffset)
                break;

            start = prev.StartOffset;
            if (!prev.IsSubword)
                break;
        }

        return start;
    }

    private static void FlushEntity(
        string originalText,
        OnnxNerOptions options,
        ref string? activeEntityType,
        ref int activeStart,
        ref int activeEnd,
        ref double probSum,
        ref int probCount,
        List<PiiMatch> destination)
    {
        if (activeEntityType != null && probCount > 0 && activeEnd > activeStart)
        {
            double avgConf = probSum / probCount;
            if (avgConf >= options.MinConfidence &&
                options.EntityTypeMap.TryGetValue(activeEntityType, out PiiType piiType))
            {
                int safeStart = Math.Clamp(activeStart, 0, originalText.Length);
                int safeEnd = Math.Clamp(activeEnd, safeStart, originalText.Length);
                int len = safeEnd - safeStart;
                if (len > 0)
                {
                    string rawValue = originalText.Substring(safeStart, len);
                    if (options.ExcludedTerms == null || !options.ExcludedTerms.Contains(rawValue))
                    {
                        destination.Add(new PiiMatch
                        {
                            RawValue = rawValue,
                            Type = piiType,
                            TypeName = options.Name,
                            Confidence = Math.Clamp(avgConf, 0.0, 1.0),
                            Index = safeStart,
                            Length = len
                        });
                    }
                }
            }
        }

        activeEntityType = null;
        activeStart = -1;
        activeEnd = -1;
        probSum = 0.0;
        probCount = 0;
    }
}
