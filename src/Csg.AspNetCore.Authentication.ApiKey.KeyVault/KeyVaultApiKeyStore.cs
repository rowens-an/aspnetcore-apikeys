using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;

namespace Csg.AspNetCore.Authentication.ApiKey.KeyVault;

public class KeyVaultApiKeyStore(IOptions<KeyVaultApiKeyStoreOptions> options) : IApiKeyStore
{
    private static readonly AzureServiceTokenProvider SAzureServiceTokenProvider = new();
    private static readonly KeyVaultClient SKeyVaultClient = new(new KeyVaultClient.AuthenticationCallback(SAzureServiceTokenProvider.KeyVaultTokenCallback));

    private readonly KeyVaultApiKeyStoreOptions _options = options.Value;
        
    private readonly Dictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Threading.SemaphoreSlim _lock = new(1, 1);

    public bool SupportsClaims => false;

    public Task<ICollection<Claim>> GetClaimsAsync(ApiKey key)
    {
        throw new NotImplementedException();
    }
               
    public async Task<ApiKey> GetKeyAsync(string clientID)
    {
        if (TryGetFromCache(clientID, out var key))
        {
            return key;
        }

        await _lock.WaitAsync().ConfigureAwait(false);

        try
        {
            // do this again because it may have been added before we aquired the lock
            if (TryGetFromCache(clientID, out key))
            {
                return key;
            }

            // get the secret from the vault
            var secretValue = await GetKeyFromVaultAsync(string.Concat(_options.ClientPrefix, clientID)).ConfigureAwait(false);

            if (secretValue == null)
            {
                return null;
            }

            // cache the secret we just got
            AddToCache(clientID, secretValue);

            return new ApiKey
            {
                Secret = secretValue,
                ClientID = clientID
            };
        }
        finally
        {
            _lock.Release();
        }
    }    

    private async Task<string> GetKeyFromVaultAsync(string secretName)
    {
        var secret = await SKeyVaultClient.GetSecretAsync($"{_options.KeyVaultUrl}secrets/{secretName}").ConfigureAwait(false);

        return secret?.Value;
    }

    private bool TryGetFromCache(string clientID, out ApiKey key)
    {
        key = null;

        if (!_cache.TryGetValue(clientID, out var secret)) return false;
        if (secret.Expires < DateTime.UtcNow)
        {
            return false;
        }

        key = new ApiKey
        {
            ClientID = clientID,
            Secret = secret.Secret
        };

        return true;

    }

    private void AddToCache(string clientID, string secret)
    {
        _cache.Add(clientID, new CacheEntry
        {
            Secret = secret,
            Expires = DateTime.UtcNow.AddMinutes(_options.CacheTimeToLiveMinutes)
        });
    }

    private class CacheEntry
    {
        public string Secret { get; init; }
        public DateTime Expires { get; init; }
    }
}