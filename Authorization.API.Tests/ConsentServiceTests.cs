using Authorization.API.Context;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.Tests;

public class ConsentServiceTests
{
    [Fact]
    public async Task HasConsentAsync_RequiresAllRequestedScopes()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        await using var db = new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();

        var consents = new ConsentService(db);
        Assert.False(await consents.HasConsentAsync("u1", "spa", ["openid", "api"]));

        await consents.GrantAsync("u1", "spa", ["openid", "profile"]);
        Assert.True(await consents.HasConsentAsync("u1", "spa", ["openid"]));
        Assert.False(await consents.HasConsentAsync("u1", "spa", ["openid", "api"]));
    }
}
