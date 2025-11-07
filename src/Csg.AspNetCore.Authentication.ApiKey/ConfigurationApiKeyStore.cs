using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class ConfigurationApiKeyStore(
    Microsoft.Extensions.Options.IOptionsMonitor<ConfigurationApiKeyStoreOptions> options)
    : IApiKeyStore
{
    public Task<ApiKey> GetKeyAsync(string clientID)
    {
        if (options.CurrentValue.Keys == null)
        {
            return Task.FromResult<ApiKey>(null);
        }

        return options.CurrentValue.Keys.TryGetValue(clientID, out var secret) ? 
            Task.FromResult(new ApiKey { ClientID = clientID, Secret = secret }) : 
            Task.FromResult<ApiKey>(null);
    }

    public bool SupportsClaims => false;

    public Task<ICollection<Claim>> GetClaimsAsync(ApiKey key)
    {
        throw new NotSupportedException();
    }
}