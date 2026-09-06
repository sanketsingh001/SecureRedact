using System.Text.Json;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Serialization;

public static class PiiEngineSerializationExtensions
{
    /// <summary>
    /// Creates JsonSerializerOptions configured with PiiJsonConverterFactory to automatically mask decorated models during serialization.
    /// </summary>
    public static JsonSerializerOptions CreateJsonSerializerOptions(this IPiiEngine engine, bool unmaskOnDeserialize = false)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNameCaseInsensitive = true
        };

        options.Converters.Add(new PiiJsonConverterFactory(engine, unmaskOnDeserialize));
        return options;
    }

    /// <summary>
    /// Serializes an object to JSON, automatically applying PII masking attributes.
    /// </summary>
    public static string SerializeWithMasking<T>(this IPiiEngine engine, T obj, bool indented = false) where T : class, new()
    {
        var options = engine.CreateJsonSerializerOptions(unmaskOnDeserialize: false);
        options.WriteIndented = indented;
        return JsonSerializer.Serialize(obj, options);
    }

    /// <summary>
    /// Deserializes JSON into an object, automatically unmasking any reversible PII tokens.
    /// </summary>
    public static T? DeserializeAndUnmask<T>(this IPiiEngine engine, string json) where T : class, new()
    {
        var options = engine.CreateJsonSerializerOptions(unmaskOnDeserialize: true);
        return JsonSerializer.Deserialize<T>(json, options);
    }
}
