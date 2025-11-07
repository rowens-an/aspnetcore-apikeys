using System;
using System.Threading.Tasks;

namespace Csg.AspNetCore.Authentication.ApiKey;

public class ApiKeyEvents
{
    public Func<RequestMessageContext, Task> OnRequestAsync { get; set; } = context => Task.CompletedTask;

    public Func<AuthenticatedEventContext, Task> OnAuthenticatedAsync { get; set; } = context => Task.CompletedTask;
}