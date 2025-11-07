using System;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class ApiKeyHandler(
    IApiKeyStore keyStore,
    IOptionsMonitor<ApiKeyOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    TimeProvider timeProvider)
    : AuthenticationHandler<ApiKeyOptions>(options, logger, encoder)
{
    private const string AuthorizationHeader = "Authorization";
    private const string AuthTypeBasic = "Basic";
    private const string AuthTypeApiKey = "ApiKey";
    private const string AuthTypeTApiKey = "TApiKey";

    private const string InvalidAuthHeaderMessage = "Invalid authorization header";
    private const string InvalidApiKeyMessage = "Invalid API Key";
    private const string InvalidClientMessage = "Invalid ClientID";
    
    public void GetApiKeyFromRequest(RequestMessageContext messageContext)
    {
        var authType = AuthTypeApiKey.AsSpan();
        ReadOnlySpan<char> rawValue;

        // first try the authorization header and then try custom header
        if (
            Request.Headers.TryGetValue(AuthorizationHeader, out var tokenValue) ||
            (Options.HeaderName != null && Request.Headers.TryGetValue(Options.HeaderName, out tokenValue))
        )
        {
            rawValue = tokenValue[0].AsSpan();
            var spaceIndex = rawValue.IndexOf(' ');

            if (spaceIndex <= 0)
            {
                messageContext.NoResult();
                return;
            }

            authType = rawValue[..spaceIndex];
            rawValue = rawValue[(spaceIndex + 1)..];
        }
        // then try query string
        else if (Options.QueryString != null && Request.Query.TryGetValue(Options.QueryString, out tokenValue))
        {
            rawValue = tokenValue[0].AsSpan();
        }
        else
        {
            // I didn't find a token anywhere, so give up
            messageContext.NoResult();
            return;
        }
            
        var sAuthTypeBasic = AuthTypeBasic.AsSpan();
        var sAuthTypeApiKey = AuthTypeApiKey.AsSpan();
        var sAuthTypeTApiKey = AuthTypeTApiKey.AsSpan();

        if (Options.HttpBasicEnabled && authType.Equals(sAuthTypeBasic, StringComparison.OrdinalIgnoreCase))
        {
            Logger.LogDebug($"HTTP Basic authentication detected.");

            var valueDecoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64CharArray(rawValue.ToArray(), 0, rawValue.Length)).AsSpan();
            var split = valueDecoded.IndexOf(':');

            messageContext.ClientID = valueDecoded[..split].ToString();
            messageContext.Token = valueDecoded[(split + 1)..].ToString();
            messageContext.AuthenticationType = AuthTypeBasic;

            return;
        } 
        if (
            (Options.TimeBasedKeyEnabled && authType.Equals(sAuthTypeApiKey, StringComparison.OrdinalIgnoreCase))
            || (Options.StaticKeyEnabled && authType.Equals(sAuthTypeTApiKey, StringComparison.OrdinalIgnoreCase))
        )
        {
            Logger.LogDebug("Authorization {AuthType} detected", authType.ToString());

            var indexOfFirstColon = rawValue.IndexOf(':');

            if (indexOfFirstColon <= 0)
            {
                messageContext.Fail(InvalidAuthHeaderMessage);
                return;
            }

            messageContext.ClientID = rawValue[..indexOfFirstColon].ToString();
            messageContext.Token = rawValue[(indexOfFirstColon + 1)..].ToString();
            messageContext.AuthenticationType = authType.ToString();

            return;
        }
        
        messageContext.Fail("Invalid authentication type");
        messageContext.NoResult();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var requestMessage = new RequestMessageContext(Context, Scheme, Options);

        await Options.Events.OnRequestAsync(requestMessage);

        // ReSharper disable once ConditionIsAlwaysTrueOrFalse
        if (requestMessage.Result is not null)
        {
            Logger.LogDebug("Using the result returned from the OnRequestAsync event");
            return requestMessage.Result;
        }

        // if the token wasn't set in OnRequestAsync(), then try to get it from the Authorization or custom header
        // ReSharper disable once HeuristicUnreachableCode
        if (requestMessage.Token == null)
        {
            GetApiKeyFromRequest(requestMessage);
        }

        if (requestMessage.Result != null)
        {
            return requestMessage.Result;
        }

        if (requestMessage?.ClientID == null)
        {
            Logger.LogDebug("ClientID not provided or is malformed");
            return AuthenticateResult.Fail(InvalidClientMessage);
        }

        var keyFromStore = await keyStore.GetKeyAsync(requestMessage.ClientID);

        if (keyFromStore == null)
        {
            Logger.LogInformation("An API key could not be found for the given ClientID");
            return AuthenticateResult.Fail(InvalidClientMessage);
        }

        if (string.IsNullOrEmpty(keyFromStore.Secret))
        {
            Logger.LogInformation("The secret for the given ClientID is null or empty");
            return AuthenticateResult.Fail(InvalidClientMessage);
        }

        var keyValidator = Options.KeyValidator;
        
        if (requestMessage.AuthenticationType.Equals(AuthTypeBasic, StringComparison.OrdinalIgnoreCase) || requestMessage.AuthenticationType.Equals(AuthTypeApiKey, StringComparison.OrdinalIgnoreCase))
        {
            keyValidator ??= new DefaultApiKeyValidator();
        }
        else if (requestMessage.AuthenticationType.Equals(AuthTypeTApiKey, StringComparison.OrdinalIgnoreCase))
        {
            keyValidator ??= new TimeBasedApiKeyValidator(timeProvider, new ApiKeyGenerator.TimeBasedTokenGenerator
            {
                IntervalSeconds = Options.TimeBasedKeyInterval,
                AllowedNumberOfDriftIntervals = Options.TimeBasedKeyTolerance
            });
        }
        else if (keyValidator == null)
        {
            return AuthenticateResult.NoResult();
        }

        if (!await keyValidator.ValidateKeyAsync(keyFromStore, requestMessage.Token))
        {
            Logger.LogInformation("The ClientID and Key pair provided in the request ({RequestMessageClientID}, {RequestMessageToken}) is not valid", requestMessage.ClientID, requestMessage.Token);
            return AuthenticateResult.Fail(InvalidApiKeyMessage);
        }

        var userResult = await CreateIdentityAsync(keyFromStore);
            
        if (userResult.Result != null)
        {
            return userResult.Result;
        }
            
        return AuthenticateResult.Success(new AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(userResult.Identity), Scheme.Name));
    }

    private async Task<AuthenticatedEventContext> CreateIdentityAsync(ApiKey key)
    {
        var claims = new List<System.Security.Claims.Claim>();

        if (keyStore.SupportsClaims)
        {
            claims.AddRange(await keyStore.GetClaimsAsync(key));
        }
        else
        {
            claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, key.ClientID));
        }

        var identity = new System.Security.Claims.ClaimsIdentity(claims, Options.AuthenticationType);
        var eventContext = new AuthenticatedEventContext(Context, Scheme, Options, key.ClientID, identity);

        await Options.Events.OnAuthenticatedAsync(eventContext);

        return eventContext;
    }
}