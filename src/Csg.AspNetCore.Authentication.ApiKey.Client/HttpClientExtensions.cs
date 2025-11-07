using Csg.ApiKeyGenerator;

namespace System.Net.Http;

public static class HttpClientExtensions
{
    private static readonly TimeBasedTokenGenerator DefaultTokenGenerator = new();

    public static void AddApiKeyAuthorizationHeader(this HttpClient client, 
        string clientID, 
        string secret, 
        DateTimeOffset utcNow,
        TimeBasedTokenGenerator tokenGenerator = null)
    {
        client.DefaultRequestHeaders.AddApiKeyAuthorizationHeader(clientID, secret, utcNow, tokenGenerator);  
    }

    // ReSharper disable once MemberCanBePrivate.Global
    public static void AddApiKeyAuthorizationHeader(this Headers.HttpRequestHeaders headers, 
        string clientID, 
        string secret, 
        DateTimeOffset utcNow, 
        TimeBasedTokenGenerator tokenGenerator = null)
    {
        tokenGenerator ??= DefaultTokenGenerator;

        var token = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Encode(tokenGenerator.ComputeToken(clientID, secret, utcNow));

        headers.Add("Authorization", $"TAPIKEY {clientID}:{token}");
    }

    // ReSharper disable once MemberCanBePrivate.Global
    public static void AddApiKeyAuthorizationHeader(this Headers.HttpRequestHeaders headers, string clientID, string secret)
    {
        secret = WebUtility.UrlEncode(secret);
        headers.Add("Authorization", $"APIKEY {clientID}:{secret}");
    }

    public static void AddApiKeyAuthorizationHeader(this HttpClient client,
        string clientID,
        string secret)
    {
        client.DefaultRequestHeaders.AddApiKeyAuthorizationHeader(clientID, secret);
    }
}