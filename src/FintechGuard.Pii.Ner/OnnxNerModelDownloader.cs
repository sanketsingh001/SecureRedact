using System.Net.Http.Headers;

namespace FintechGuard.Pii.Ner;

/// <summary>
/// Pure-.NET helper that downloads and caches quantized CPU-ready Hugging Face ONNX NER weights
/// without requiring Python, pip, or Optimum.
/// </summary>
public static class OnnxNerModelDownloader
{
    public const string DefaultMultilingualRepoId = "Xenova/distilbert-base-multilingual-cased-ner-hrl";
    public const string DefaultQuantizedModelFile = "onnx/model_quantized.onnx";

    /// <summary>
    /// Ensures the specified quantized Hugging Face ONNX NER model files (<c>model_quantized.onnx</c>,
    /// <c>vocab.txt</c>, <c>config.json</c>, <c>tokenizer_config.json</c>) exist locally in <paramref name="targetDirectory"/>,
    /// downloading missing files atomically with optional progress reporting and <c>HF_TOKEN</c> support.
    /// </summary>
    public static async Task<string> EnsureModelAsync(
        string targetDirectory,
        string repoId = DefaultMultilingualRepoId,
        string modelFile = DefaultQuantizedModelFile,
        string? hfToken = null,
        HttpClient? httpClient = null,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(repoId);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelFile);

        Directory.CreateDirectory(targetDirectory);

        string[] files = [modelFile, "vocab.txt", "config.json", "tokenizer_config.json"];
        string? token = !string.IsNullOrWhiteSpace(hfToken)
            ? hfToken
            : Environment.GetEnvironmentVariable("HF_TOKEN");

        bool ownsClient = httpClient == null;
        HttpClient client = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(10)
        };

        try
        {
            foreach (string relPath in files)
            {
                string destPath = Path.Combine(targetDirectory, relPath.Replace('/', Path.DirectorySeparatorChar));
                if (File.Exists(destPath) && new FileInfo(destPath).Length > 0)
                {
                    progress?.Report($"Cached: {relPath}");
                    continue;
                }

                string? parentDir = Path.GetDirectoryName(destPath);
                if (!string.IsNullOrEmpty(parentDir))
                    Directory.CreateDirectory(parentDir);

                string url = $"https://huggingface.co/{repoId}/resolve/main/{relPath}";
                string tmpPath = destPath + $".tmp.{Guid.NewGuid():N}";

                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.UserAgent.ParseAdd("SecureRedact.Ner/1.3.0");
                    if (!string.IsNullOrWhiteSpace(token))
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                    using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                        .ConfigureAwait(false);
                    response.EnsureSuccessStatusCode();

                    await using (var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
                    await using (var fileStream = new FileStream(
                        tmpPath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.None,
                        bufferSize: 81920,
                        useAsync: true))
                    {
                        await responseStream.CopyToAsync(fileStream, cancellationToken).ConfigureAwait(false);
                        await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }

                    File.Move(tmpPath, destPath, overwrite: true);
                    progress?.Report($"Downloaded: {relPath}");
                }
                catch
                {
                    try
                    {
                        if (File.Exists(tmpPath))
                            File.Delete(tmpPath);
                    }
                    catch
                    {
                    }
                    throw;
                }
            }

            return targetDirectory;
        }
        finally
        {
            if (ownsClient)
                client.Dispose();
        }
    }
}
