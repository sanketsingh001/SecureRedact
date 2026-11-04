using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Context;

/// <summary>
/// Maintains a registry of JSON key/property name heuristics to adjust the confidence score
/// of detected PII. For example, a 10-digit number under the key "pan_number" gets a confidence boost.
/// </summary>
public class KeyHintRegistry
{
    private readonly Dictionary<string, (PiiType Type, double BoostDelta)> _hints = new(StringComparer.OrdinalIgnoreCase);

    public KeyHintRegistry()
    {
        // Indian Identifiers
        AddHint("aadhaar", PiiType.Aadhaar, 0.30);
        AddHint("aadhar", PiiType.Aadhaar, 0.30);
        AddHint("pan", PiiType.Pan, 0.25);
        AddHint("pan_number", PiiType.Pan, 0.30);
        AddHint("gstin", PiiType.Gstin, 0.30);

        // Global Financial
        AddHint("card", PiiType.CreditCard, 0.25);
        AddHint("card_number", PiiType.CreditCard, 0.30);
        AddHint("credit_card", PiiType.CreditCard, 0.30);
        AddHint("ssn", PiiType.UsSsn, 0.30);
        
        // PII Contact
        AddHint("email", PiiType.Email, 0.20);
        AddHint("ip", PiiType.IpAddress, 0.20);
        AddHint("ip_address", PiiType.IpAddress, 0.20);
        AddHint("phone", PiiType.GenericPhone, 0.20);
        AddHint("mobile", PiiType.GenericPhone, 0.20);

        // Penalize keys that often contain numbers mistaken for PII
        AddHint("quantity", PiiType.CreditCard, -0.50);
        AddHint("amount", PiiType.CreditCard, -0.50);
        AddHint("transaction_id", PiiType.CreditCard, -0.40);
        AddHint("invoice_number", PiiType.CreditCard, -0.40);
        AddHint("id", PiiType.CreditCard, -0.30);
        AddHint("count", PiiType.CreditCard, -0.50);
    }

    /// <summary>
    /// Adds or updates a hint for a specific key.
    /// </summary>
    public void AddHint(string key, PiiType targetType, double boostDelta)
    {
        _hints[key] = (targetType, boostDelta);
    }

    /// <summary>
    /// Retrieves the confidence boost delta for a given property name and detected PII type.
    /// </summary>
    public double GetBoost(string? propertyName, PiiType detectedType)
    {
        if (string.IsNullOrWhiteSpace(propertyName))
            return 0.0;

        // Exact match or partial match (e.g. "customer_pan")
        foreach (var kvp in _hints)
        {
            if (propertyName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                if (kvp.Value.Type == detectedType)
                {
                    return kvp.Value.BoostDelta;
                }
            }
        }

        return 0.0;
    }
}
