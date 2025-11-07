using System;
using Microsoft.Extensions.Logging;

namespace Csg.AspNetCore.Authentication.ApiKey.Tests;

public class FakeLoggerFactory : ILoggerFactory
{
    public void AddProvider(ILoggerProvider provider)
    {
        throw new NotImplementedException();
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new FakeLogger();
    }

    public void Dispose()
    {
    }
}