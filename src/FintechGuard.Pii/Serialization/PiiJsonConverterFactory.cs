using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using FintechGuard.Pii.Attributes;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Masking;

namespace FintechGuard.Pii.Serialization;

/// <summary>
/// System.Text.Json converter factory that automatically applies [PiiMask] and [CustomPiiRule] attributes
/// during model serialization and deserialization.
/// </summary>
public sealed class PiiJsonConverterFactory : JsonConverterFactory
{
    private readonly IPiiEngine _engine;
    private readonly bool _unmaskOnDeserialize;

    public PiiJsonConverterFactory(IPiiEngine engine, bool unmaskOnDeserialize = false)
    {
        _engine = engine;
        _unmaskOnDeserialize = unmaskOnDeserialize;
    }

    public override bool CanConvert(Type typeToConvert)
    {
        // Applies to POCO / class types (excluding primitives, strings, collections directly)
        return typeToConvert.IsClass &&
               typeToConvert != typeof(string) &&
               !typeof(System.Collections.IEnumerable).IsAssignableFrom(typeToConvert);
    }

    public override JsonConverter? CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        Type converterType = typeof(PiiPocoConverter<>).MakeGenericType(typeToConvert);
        return (JsonConverter)Activator.CreateInstance(converterType, _engine, _unmaskOnDeserialize)!;
    }
}

internal sealed class PiiPocoConverter<T> : JsonConverter<T> where T : class, new()
{
    private readonly IPiiEngine _engine;
    private readonly bool _unmaskOnDeserialize;
    private readonly List<PropertyMetadata> _properties = new();

    private record PropertyMetadata(
        PropertyInfo Property,
        string JsonPropertyName,
        PiiMaskAttribute? MaskAttr,
        CustomPiiRuleAttribute? CustomAttr,
        bool IsIgnored);

    public PiiPocoConverter(IPiiEngine engine, bool unmaskOnDeserialize)
    {
        _engine = engine;
        _unmaskOnDeserialize = unmaskOnDeserialize;

        foreach (var prop in typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!prop.CanRead) continue;

            bool isIgnored = prop.GetCustomAttribute<PiiIgnoreAttribute>() != null;
            var maskAttr = prop.GetCustomAttribute<PiiMaskAttribute>();
            var customAttr = prop.GetCustomAttribute<CustomPiiRuleAttribute>();

            var jsonAttr = prop.GetCustomAttribute<JsonPropertyNameAttribute>();
            string name = jsonAttr?.Name ?? prop.Name;

            _properties.Add(new PropertyMetadata(prop, name, maskAttr, customAttr, isIgnored));
        }
    }

    public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("Expected StartObject token.");

        T instance = new T();

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
                return instance;

            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string? propName = reader.GetString();
                reader.Read();

                var meta = _properties.FirstOrDefault(p =>
                    string.Equals(p.JsonPropertyName, propName, StringComparison.OrdinalIgnoreCase));

                if (meta == null || !meta.Property.CanWrite)
                {
                    reader.Skip();
                    continue;
                }

                if (meta.Property.PropertyType == typeof(string))
                {
                    string? rawVal = reader.GetString();
                    if (rawVal != null && _unmaskOnDeserialize)
                    {
                        rawVal = _engine.UnmaskValue(rawVal);
                    }
                    meta.Property.SetValue(instance, rawVal);
                }
                else
                {
                    object? val = JsonSerializer.Deserialize(ref reader, meta.Property.PropertyType, options);
                    meta.Property.SetValue(instance, val);
                }
            }
        }

        return instance;
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        foreach (var meta in _properties)
        {
            object? propVal = meta.Property.GetValue(value);
            if (propVal == null)
            {
                writer.WriteNull(meta.JsonPropertyName);
                continue;
            }

            if (propVal is string strVal && !meta.IsIgnored)
            {
                string outputVal = strVal;

                if (meta.MaskAttr != null)
                {
                    outputVal = _engine.MaskValue(strVal, meta.MaskAttr.PiiType);
                }
                else if (meta.CustomAttr != null)
                {
                    outputVal = _engine.MaskValue(strVal);
                }
                else
                {
                    // Dynamic scan if string
                    outputVal = _engine.MaskValue(strVal);
                }

                writer.WriteString(meta.JsonPropertyName, outputVal);
            }
            else
            {
                writer.WritePropertyName(meta.JsonPropertyName);
                JsonSerializer.Serialize(writer, propVal, propVal.GetType(), options);
            }
        }

        writer.WriteEndObject();
    }
}
