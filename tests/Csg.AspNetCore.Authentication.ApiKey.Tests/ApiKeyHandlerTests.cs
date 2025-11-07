using Microsoft.AspNetCore.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Microsoft.Extensions.Time.Testing;

namespace Csg.AspNetCore.Authentication.ApiKey.Tests;

[TestClass]
public class ApiKeyHandlerTests
{
    private const string Header = "Authorization";
    private readonly FakeTimeProvider _fakeTimeProvider = new();
    
    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithNoToken()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();
            
        Assert.IsFalse(authResult.Succeeded);
        Assert.IsTrue(authResult.None);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithMalformedHeader()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append(Header, "AuthTypeNotHandled");
        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsFalse(authResult.Succeeded);
        Assert.IsTrue(authResult.None);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithMalformedToken()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append(Header, "APIKEY ClienIDWithoutKey");
        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsFalse(authResult.Succeeded);
        Assert.IsFalse(authResult.None);
        Assert.IsNotNull(authResult.Failure);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithInvalidToken()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append(Header, "ApiKey ClientID:InvalidSecret");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsFalse(authResult.Succeeded);
        Assert.IsFalse(authResult.None);
        Assert.IsNotNull(authResult.Failure);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithValidStaticToken()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append("Authorization", "ApiKey TestName:TestKey");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithValidStaticTokenInCustomHeader()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append("Authorization", "ApiKey TestName:TestKey");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithValidStaticTokenInQueryString()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Query = new QueryCollection(new System.Collections.Generic.Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "_apikey", new Microsoft.Extensions.Primitives.StringValues("TestName:TestKey") }
        });

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithValidStaticTokenAlternateCase()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append("Authorization", "ApiKey testNAME:TestKey");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithValidTimeBasedToken()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);
        var gen = new ApiKeyGenerator.TimeBasedTokenGenerator();

        var token = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Encode(gen.ComputeToken("TestName", "TestKey", _fakeTimeProvider.GetUtcNow()));

        context.Request.Headers.Append("Authorization", $"TAPIKEY TestName:{token}");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithValidTimeBasedTokenAlternateCase()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);
        var gen = new ApiKeyGenerator.TimeBasedTokenGenerator();

        var token = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Encode(gen.ComputeToken("testNAME", "TestKey", _fakeTimeProvider.GetUtcNow()));

        context.Request.Headers.Append("Authorization", $"TAPIKEY testNAME:{token}");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithOutOfRangeTimeBasedToken()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);
        var gen = new ApiKeyGenerator.TimeBasedTokenGenerator();

        var token = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Encode(gen.ComputeToken("TestName", "TestKey", _fakeTimeProvider.GetUtcNow().AddSeconds(120)));

        context.Request.Headers.Append("Authorization", $"TAPIKEY TestName:{token}");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsFalse(authResult.Succeeded);
        Assert.IsNull(authResult.Principal);
    }

    [TestMethod]
    public void ApiKeyHandler_OnRequestEvent()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        handler.Options.Events.OnRequestAsync = (ctx) =>
        {
            ctx.AuthenticationType = "ApiKey";
            ctx.ClientID = "TestName";
            ctx.Token = "TestKey";

            return System.Threading.Tasks.Task.CompletedTask;
        };

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public void ApiKeyHandler_AuthenticatedEvent()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        handler.Options.Events.OnAuthenticatedAsync = (ctx) =>
        {
            ctx.Identity.AddClaim(new System.Security.Claims.Claim("Foo", "Bar"));

            return System.Threading.Tasks.Task.CompletedTask;
        };

        context.Request.Headers.Append("Authorization", "ApiKey TestName:TestKey");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Principal.HasClaim(x => x.Type == "Foo"));
    }

    [TestMethod]
    public void ApiKeyHandler_HandleRequestWithHttpBasic()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);
        var gen = new ApiKeyGenerator.TimeBasedTokenGenerator();
        var value = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"TestName:TestKey"));

        context.Request.Headers.Append("Authorization", $"Basic {value}");

        var authResult = handler.AuthenticateAsync().ConfigureAwait(false).GetAwaiter().GetResult();

        Assert.IsTrue(authResult.Succeeded);
        Assert.IsTrue(authResult.Principal.Identity.IsAuthenticated);
        Assert.AreEqual("TestName", authResult.Principal.Identity.Name);
    }

    [TestMethod]
    public async System.Threading.Tasks.Task ApiKeyHandler_BlankSecretIsNotValid()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append("Authorization", "ApiKey BlankKey:");

        var authResult = await handler.AuthenticateAsync();

        Assert.IsFalse(authResult.Succeeded);

        Assert.IsFalse(authResult.Succeeded);
    }

    [TestMethod]
    public async System.Threading.Tasks.Task ApiKeyHandler_NullSecretIsNotValid()
    {
        var context = new DefaultHttpContext();
        var handler = CreateHandler(context);

        context.Request.Headers.Append("Authorization", "ApiKey NullKey:");
        var authResult = await handler.AuthenticateAsync();

        Assert.IsFalse(authResult.Succeeded);

    }

    private ApiKeyHandler CreateHandler(HttpContext context)
    {
        var keyStore = new FakeKeyStore();
        var options = new FakeOptionsMonitor<ApiKeyOptions> { CurrentValue = new ApiKeyOptions() };
        var logger = new FakeLoggerFactory();
        _fakeTimeProvider.SetUtcNow(new DateTimeOffset(2015, 09, 25, 00, 00, 00, TimeSpan.Zero));

        var b = new Microsoft.AspNetCore.Authentication.AuthenticationSchemeBuilder(ApiKeyDefaults.Name)
        {
            HandlerType = typeof(ApiKeyHandler),
            DisplayName = "API Key"
        };

        var handler = new ApiKeyHandler(keyStore, options, logger, System.Text.Encodings.Web.UrlEncoder.Default, _fakeTimeProvider);

        handler.InitializeAsync(b.Build(), context).ConfigureAwait(false).GetAwaiter().GetResult();

        return handler;
    }
}