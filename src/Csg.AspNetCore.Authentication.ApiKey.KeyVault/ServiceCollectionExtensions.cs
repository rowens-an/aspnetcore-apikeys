using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Csg.AspNetCore.Authentication.ApiKey.KeyVault;

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static void AddKeyVaultApiKeyStore(this IServiceCollection services, Action<KeyVaultApiKeyStoreOptions> setupAction = null, IConfigurationSection configurationSection = null)
    {
        services.TryAddSingleton<Csg.AspNetCore.Authentication.ApiKey.IApiKeyStore, KeyVaultApiKeyStore>();

        if (setupAction != null)
        {
            services.Configure(setupAction);
        }
    }
}