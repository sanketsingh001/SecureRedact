namespace FintechGuard.Pii.Ner;

/// <summary>
/// Configuration options for the sub-millisecond pure-CPU Tier 1 Contextual &amp; Gazetteer NER recognizer.
/// </summary>
public sealed class ContextualNerOptions
{
    /// <summary>
    /// Recognizer display name used in audit detections.
    /// </summary>
    public string Name { get; set; } = "Contextual_CPU_NER";

    /// <summary>
    /// JSON property keys to target (matched on identifier boundaries).
    /// Leave empty to automatically gate unstructured natural-language fields.
    /// </summary>
    public string[] TargetKeys { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Confidence assigned to detected entities. Default: 0.85.
    /// </summary>
    public double Confidence { get; set; } = 0.85;

    /// <summary>
    /// Detect person names via honorifics, multilingual triggers (English &amp; Hindi), and curated name lexicons.
    /// </summary>
    public bool DetectPersonNames { get; set; } = true;

    /// <summary>
    /// Detect street/residential addresses anchored on street suffixes, house/flat numbers, PIN codes, and address triggers.
    /// </summary>
    public bool DetectAddresses { get; set; } = true;

    /// <summary>
    /// Opt-in detection of organization/company names ending in corporate designators (Ltd, Pvt Ltd, LLP, Inc, Bank, etc.).
    /// </summary>
    public bool DetectOrganizations { get; set; } = false;

    /// <summary>
    /// When TargetKeys is empty, skip structured tokens (single-word ASCII codes, UUIDs, numbers) and only inspect natural-language text.
    /// </summary>
    public bool AutoGateUnstructuredText { get; set; } = true;

    public HashSet<string> AdditionalFirstNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> AdditionalLastNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> AdditionalAddressKeywords { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> StopWords { get; } = new(StringComparer.OrdinalIgnoreCase);
}
