using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class AuthenticatedEventContext(
    HttpContext context,
    AuthenticationScheme scheme,
    ApiKeyOptions options,
    string clientID,
    System.Security.Claims.ClaimsIdentity identity)
    : HandleRequestContext<ApiKeyOptions>(context, scheme, options)
{
    public string ClientID { get; protected set; } = clientID;

    public System.Security.Claims.ClaimsIdentity Identity { get; protected set; } = identity;
}