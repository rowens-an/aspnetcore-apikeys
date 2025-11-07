using System;

namespace Csg.AspNetCore.Authentication.ApiKey.Tests;

public class FakeOptionsMonitor<T> : Microsoft.Extensions.Options.IOptionsMonitor<T>
{
    public FakeOptionsMonitor()
    {

    }

    public FakeOptionsMonitor(T options)
    {
        CurrentValue = options;
    }

    public T CurrentValue { get; set; }

    public T Get(string name)
    {
        return CurrentValue;
    }

    public IDisposable OnChange(Action<T, string> listener)
    {
        throw new NotImplementedException();
    }
}