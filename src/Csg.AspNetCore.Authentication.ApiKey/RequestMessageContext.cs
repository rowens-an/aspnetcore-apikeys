using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class RequestMessageContext(HttpContext context, AuthenticationScheme scheme, ApiKeyOptions options)
    : ResultContext<ApiKeyOptions>(context, scheme, options)
{
    public string AuthenticationType { get; set; }

    public string ClientID { get; set; }

    public string Token { get; set; }
}