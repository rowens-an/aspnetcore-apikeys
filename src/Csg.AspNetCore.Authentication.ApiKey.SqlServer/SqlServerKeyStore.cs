using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Dapper;

namespace Csg.AspNetCore.Authentication.ApiKey.SqlServer;

public class SqlServerKeyStore(string connectionString) : IApiKeyStore
{
    public bool EnableClaimsStore { get; set; } = false;

    public bool SupportsClaims => EnableClaimsStore;

    public string SelectKeyByClientIdQuery { get; set; } = "SELECT [ClientID], [Secret] FROM [ApiKey] WHERE [ClientID] = @clientID;";

    public string SelectClaimsByClientIdQuery { get; set; } = "";

    public async Task<ApiKey> GetKeyAsync(string clientID)
    {
        await using var conn = await OpenConnectionAsync();
        return await conn.QuerySingleAsync<ApiKey>(SelectKeyByClientIdQuery, new
        {
            clientID
        });
    }

    public Task<ICollection<Claim>> GetClaimsAsync(ApiKey key)
    {
        throw new NotImplementedException();
    }       
    
    private async Task<Microsoft.Data.SqlClient.SqlConnection> OpenConnectionAsync()
    {
        var conn = new Microsoft.Data.SqlClient.SqlConnection(connectionString);

        await conn.OpenAsync();

        return conn;
    }
}