using System.Collections.Generic;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class ConfigurationApiKeyStoreOptions
{
    public IDictionary<string, string> Keys { get; set; }
}