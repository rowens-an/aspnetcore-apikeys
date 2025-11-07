using System;
using System.Threading.Tasks;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class TimeBasedApiKeyValidator(TimeProvider timeProvider, ApiKeyGenerator.TimeBasedTokenGenerator generator)
    : IApiKeyValidator
{
    public TimeBasedApiKeyValidator(TimeProvider timeProvider) : this(timeProvider, new ApiKeyGenerator.TimeBasedTokenGenerator())
    { }

    public Task<bool> ValidateKeyAsync(ApiKey keyFromStore, string token)
    {
        var now = timeProvider.GetUtcNow();

        var tokenBytes = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Decode(token);

        return Task.FromResult(generator.ValidateToken(keyFromStore.ClientID, keyFromStore.Secret, tokenBytes, now));
    }
}