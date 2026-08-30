using Authorization.API.Context;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Authorization.API.Tests;

public class RefreshTokenRotationTests
{
    [Fact]
    public async Task RotateRefreshToken_DetectsReuseAndRevokesFamily()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var db = new ApplicationDbContext(options);
        await db.Database.EnsureCreatedAsync();

        db.Clients.Add(new Client
        {
            ClientId = "spa",
            RequireClientSecret = false,
            RequirePkce = true
        });
        await db.SaveChangesAsync();

        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Jwt:SecretKey"] = "DEV_ONLY_JWT_SIGNING_KEY_MUST_BE_LONG_ENOUGH_32",
            ["Jwt:Issuer"] = "test",
            ["Jwt:Audience"] = "test"
        }).Build();

        var tokens = new TokenService(config, db);
        var first = tokens.GenerateRefreshToken();
        await tokens.StoreRefreshToken(first, clientId: "spa");

        var rotated = await tokens.RotateRefreshToken(first, clientId: "spa");
        Assert.False(rotated.IsInvalid);
        Assert.False(string.IsNullOrEmpty(rotated.NewRefreshToken));

        var reuse = await tokens.RotateRefreshToken(first, clientId: "spa");
        Assert.True(reuse.ReuseDetected);

        var familyStillValid = await tokens.RotateRefreshToken(rotated.NewRefreshToken, clientId: "spa");
        Assert.True(familyStillValid.IsInvalid);
        Assert.True(familyStillValid.ReuseDetected);
    }
}
