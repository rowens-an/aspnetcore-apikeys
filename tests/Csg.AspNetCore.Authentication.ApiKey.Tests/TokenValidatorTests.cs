using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Microsoft.Extensions.Time.Testing;

namespace Csg.AspNetCore.Authentication.ApiKey.Tests;

[TestClass]
public class TokenValidatorTests
{
    private readonly FakeTimeProvider _fakeTimeProvider = new();
    
    [TestMethod]
    public async System.Threading.Tasks.Task DefaultApiKeyValidator_ValidateKeyAsyncReturnsFalseOnEmptySecret()
    {
        var validator = new DefaultApiKeyValidator();
        var result = await validator.ValidateKeyAsync(new ApiKey { ClientID = "foo", Secret = "" }, "Test");

        Assert.IsFalse(result);
    }

    [TestMethod]
    public async System.Threading.Tasks.Task DefaultApiKeyValidator_ValidateKeyAsyncReturnsFalseOnNullSecret()
    {
        var validator = new DefaultApiKeyValidator();
        var result = await validator.ValidateKeyAsync(new ApiKey { ClientID = "foo", Secret = null }, "Test");

        Assert.IsFalse(result);
    }

    [TestMethod]
    public async System.Threading.Tasks.Task TimeBasedApiKeyValidator_ValidateKeyAsyncReturnsFalseOnEmptySecret()
    {
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
        {
            var validator = new TimeBasedApiKeyValidator(_fakeTimeProvider);
            var result = await validator.ValidateKeyAsync(new ApiKey { ClientID = "foo", Secret = "" }, "Test");
        });
    }

    [TestMethod]
    public async System.Threading.Tasks.Task TimeBasedApiKeyValidator_ValidateKeyAsyncReturnsFalseOnNullSecret()
    {
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
        {
            var validator = new TimeBasedApiKeyValidator(_fakeTimeProvider);
            var result = await validator.ValidateKeyAsync(new ApiKey { ClientID = "foo", Secret = null }, "Test");
        });
    }

}