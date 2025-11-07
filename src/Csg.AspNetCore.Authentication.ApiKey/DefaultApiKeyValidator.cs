using System;
using System.Threading.Tasks;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class DefaultApiKeyValidator : IApiKeyValidator
{
    public Task<bool> ValidateKeyAsync(ApiKey keyFromStore, string token)
    {
        ArgumentNullException.ThrowIfNull(keyFromStore);
        ArgumentNullException.ThrowIfNull(token);

        return keyFromStore.Secret == null ? 
            Task.FromResult(false) :
            //TODO: should do a slow compare
            Task.FromResult(keyFromStore.Secret.Equals(token));
    }
}