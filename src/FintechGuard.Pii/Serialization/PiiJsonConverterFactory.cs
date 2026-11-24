using System.Linq.Expressions;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using FintechGuard.Pii.Attributes;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Serialization;

/// <summary>
/// System.Text.Json converter factory that automatically applies [PiiMask], [CustomPiiRule], and [PiiIgnore]
/// attributes during model serialization and deserialization using compiled expression delegates.
/// </summary>
public sealed class PiiJsonConverterFactory : JsonConverterFactory
{
    private readonly IPiiEngine _engine;
    private readonly bool _unmaskOnDeserialize;

    public PiiJsonConverterFactory(IPiiEngine engine, bool unmaskOnDeserialize = false)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _unmaskOnDeserialize = unmaskOnDeserialize;
    }

    public override bool CanConvert(Type typeToConvert)
    {
        if (!typeToConvert.IsClass || typeToConvert.IsAbstract || typeToConvert.IsInterface)
            return false;

        if (typeToConvert == typeof(string) ||
            typeToConvert == typeof(Type) ||
            typeof(System.Collections.IEnumerable).IsAssignableFrom(typeToConvert) ||
            typeof(Stream).IsAssignableFrom(typeToConvert) ||
            typeof(JsonDocument).IsAssignableFrom(typeToConvert) ||
            typeof(JsonElement).IsAssignableFrom(typeToConvert) ||
            typeof(Delegate).IsAssignableFrom(typeToConvert))
            return false;

        // Only convert POCOs that actually have a public parameterless constructor
        return typeToConvert.GetConstructor(Type.EmptyTypes) != null;
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
    private readonly Dictionary<string, PropertyMetadata> _propertyLookup = new(StringComparer.OrdinalIgnoreCase);

    private sealed class PropertyMetadata
    {
        public required Func<T, object?> Getter { get; init; }
        public required Action<T, object?>? Setter { get; init; }
        public required Type PropertyType { get; init; }
        public required string JsonPropertyName { get; init; }
        public PiiMaskAttribute? MaskAttr { get; init; }
        public CustomPiiRuleAttribute? CustomAttr { get; init; }
        public Regex? CustomRegex { get; init; }
        public bool IsIgnored { get; init; }
    }

    public PiiPocoConverter(IPiiEngine engine, bool unmaskOnDeserialize)
    {
        _engine = engine;
        _unmaskOnDeserialize = unmaskOnDeserialize;

        foreach (var prop in typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!prop.CanRead || prop.GetIndexParameters().Length > 0)
                continue;

            if (prop.GetCustomAttribute<JsonIgnoreAttribute>() != null)
                continue;

            bool isIgnored = prop.GetCustomAttribute<PiiIgnoreAttribute>() != null;
            var maskAttr = prop.GetCustomAttribute<PiiMaskAttribute>();
            var customAttr = prop.GetCustomAttribute<CustomPiiRuleAttribute>();
            Regex? customRegex = customAttr != null
                ? new Regex(customAttr.Pattern, RegexOptions.Compiled, TimeSpan.FromMilliseconds(100))
                : null;

            var jsonAttr = prop.GetCustomAttribute<JsonPropertyNameAttribute>();
            string name = jsonAttr?.Name ?? prop.Name;

            var meta = new PropertyMetadata
            {
                Getter = CompileGetter(prop),
                Setter = prop.CanWrite ? CompileSetter(prop) : null,
                PropertyType = prop.PropertyType,
                JsonPropertyName = name,
                MaskAttr = maskAttr,
                CustomAttr = customAttr,
                CustomRegex = customRegex,
                IsIgnored = isIgnored
            };

            _properties.Add(meta);
            _propertyLookup[name] = meta;
        }
    }

    public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
            return null;

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

                if (propName == null || !_propertyLookup.TryGetValue(propName, out var meta) || meta.Setter == null)
                {
                    reader.Skip();
                    continue;
                }

                if (meta.PropertyType == typeof(string))
                {
                    string? rawVal = reader.TokenType == JsonTokenType.Null ? null : reader.GetString();
                    if (rawVal != null && _unmaskOnDeserialize && !meta.IsIgnored)
                    {
                        rawVal = _engine.UnmaskValue(rawVal);
                    }
                    meta.Setter(instance, rawVal);
                }
                else
                {
                    object? val = JsonSerializer.Deserialize(ref reader, meta.PropertyType, options);
                    meta.Setter(instance, val);
                }
            }
        }

        return instance;
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        for (int i = 0; i < _properties.Count; i++)
        {
            var meta = _properties[i];
            object? propVal = meta.Getter(value);
            if (propVal == null)
            {
                writer.WriteNull(meta.JsonPropertyName);
                continue;
            }

            if (propVal is string strVal && !meta.IsIgnored)
            {
                string outputVal;

                if (meta.MaskAttr != null)
                {
                    MaskingStrategy? strategyOverride = meta.MaskAttr.HasExplicitStrategy ? meta.MaskAttr.Strategy : null;
                    char? maskCharOverride = meta.MaskAttr.HasExplicitMaskChar ? meta.MaskAttr.MaskChar : null;

                    if (_engine is PiiEngine concreteEngine)
                    {
                        outputVal = concreteEngine.MaskValue(strVal, meta.MaskAttr.PiiType, null, strategyOverride, maskCharOverride);
                    }
                    else
                    {
                        outputVal = _engine.MaskValue(strVal, meta.MaskAttr.PiiType);
                    }
                }
                else if (meta.CustomAttr != null && meta.CustomRegex != null)
                {
                    outputVal = ApplyCustomRule(strVal, meta.CustomAttr, meta.CustomRegex);
                }
                else
                {
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

    private string ApplyCustomRule(string input, CustomPiiRuleAttribute attr, Regex regex)
    {
        return regex.Replace(input, match =>
        {
            string raw = match.Value;
            string visual = CreateCustomVisualMask(raw, attr.MaskChar, attr.KeepPrefix, attr.KeepSuffix);

            if (_engine is PiiEngine concreteEngine)
            {
                MaskingStrategy? strategyOverride = attr.HasExplicitStrategy ? attr.Strategy : null;
                return concreteEngine.ProtectCustomMatch(raw, visual, PiiType.Custom, strategyOverride);
            }

            return visual;
        });
    }

    private static string CreateCustomVisualMask(string raw, char maskChar, int keepPrefix, int keepSuffix)
    {
        int len = raw.Length;
        int p = Math.Max(0, keepPrefix);
        int s = Math.Max(0, keepSuffix);

        if (len <= p + s)
            return new string(maskChar, len);

        return string.Create(len, (raw, maskChar, p, s), static (span, state) =>
        {
            if (state.p > 0)
                state.raw.AsSpan(0, state.p).CopyTo(span);
            span.Slice(state.p, state.raw.Length - state.p - state.s).Fill(state.maskChar);
            if (state.s > 0)
                state.raw.AsSpan(state.raw.Length - state.s, state.s).CopyTo(span.Slice(state.raw.Length - state.s));
        });
    }

    private static Func<T, object?> CompileGetter(PropertyInfo prop)
    {
        var instanceParam = Expression.Parameter(typeof(T), "instance");
        var propertyAccess = Expression.Property(instanceParam, prop);
        var boxed = Expression.Convert(propertyAccess, typeof(object));
        return Expression.Lambda<Func<T, object?>>(boxed, instanceParam).Compile();
    }

    private static Action<T, object?>? CompileSetter(PropertyInfo prop)
    {
        if (prop.GetSetMethod(nonPublic: false) == null)
            return null;

        var instanceParam = Expression.Parameter(typeof(T), "instance");
        var valueParam = Expression.Parameter(typeof(object), "value");
        var castValue = Expression.Convert(valueParam, prop.PropertyType);
        var assign = Expression.Assign(Expression.Property(instanceParam, prop), castValue);
        return Expression.Lambda<Action<T, object?>>(assign, instanceParam, valueParam).Compile();
    }
}
