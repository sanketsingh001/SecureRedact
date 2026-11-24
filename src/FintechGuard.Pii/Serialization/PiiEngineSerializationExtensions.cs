using System.Runtime.CompilerServices;
using System.Text.Json;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Serialization;

public static class PiiEngineSerializationExtensions
{
    private sealed class CachedSerializerOptions
    {
        public required JsonSerializerOptions MaskCompact { get; init; }
        public required JsonSerializerOptions MaskIndented { get; init; }
        public required JsonSerializerOptions Unmask { get; init; }
    }

    private static readonly ConditionalWeakTable<IPiiEngine, CachedSerializerOptions> OptionsCache = new();

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
    /// Serializes an object to JSON, automatically applying PII masking attributes (with cached JsonSerializerOptions metadata).
    /// </summary>
    public static string SerializeWithMasking<T>(this IPiiEngine engine, T obj, bool indented = false) where T : class, new()
    {
        var cached = GetOrCreateCachedOptions(engine);
        return JsonSerializer.Serialize(obj, indented ? cached.MaskIndented : cached.MaskCompact);
    }

    /// <summary>
    /// Deserializes JSON into an object, automatically unmasking any reversible PII tokens (with cached JsonSerializerOptions metadata).
    /// </summary>
    public static T? DeserializeAndUnmask<T>(this IPiiEngine engine, string json) where T : class, new()
    {
        var cached = GetOrCreateCachedOptions(engine);
        return JsonSerializer.Deserialize<T>(json, cached.Unmask);
    }

    private static CachedSerializerOptions GetOrCreateCachedOptions(IPiiEngine engine)
    {
        return OptionsCache.GetValue(engine, static e =>
        {
            var compact = e.CreateJsonSerializerOptions(unmaskOnDeserialize: false);
            var indented = e.CreateJsonSerializerOptions(unmaskOnDeserialize: false);
            indented.WriteIndented = true;
            var unmask = e.CreateJsonSerializerOptions(unmaskOnDeserialize: true);

            return new CachedSerializerOptions
            {
                MaskCompact = compact,
                MaskIndented = indented,
                Unmask = unmask
            };
        });
    }
}
