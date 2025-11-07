namespace Csg.AspNetCore.Authentication.ApiKey;

public interface IApiKeyValidator
{
    System.Threading.Tasks.Task<bool> ValidateKeyAsync(ApiKey keyFromStore, string token);
}