using Authorization.API.Context;
using Authorization.API.Data;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Authorization.API.Tests;

public class DatabaseInitializerTests
{
    [Fact]
    public async Task SeedAsync_CreatesDemoUsersAndClient()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(connection));
        services.AddIdentity<ApplicationUser, ApplicationRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        services.AddSingleton<IClientSecretHasher, ClientSecretHasher>();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureCreatedAsync();

        var options = new SeedOptions { Enabled = true };
        await DatabaseInitializer.SeedAsync(scope.ServiceProvider, options, NullLogger.Instance);

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var admin = await userManager.FindByEmailAsync(options.AdminEmail);
        var demo = await userManager.FindByEmailAsync(options.DemoUserEmail);
        var client = await db.Clients.SingleAsync(c => c.ClientId == options.DemoClientId);

        Assert.NotNull(admin);
        Assert.NotNull(demo);
        Assert.True(await userManager.IsInRoleAsync(admin!, "Administrator"));
        var hasher = scope.ServiceProvider.GetRequiredService<IClientSecretHasher>();
        Assert.True(hasher.Verify(client.ClientSecret, options.DemoClientSecret));
        Assert.NotEqual(options.DemoClientSecret, client.ClientSecret);
        Assert.Contains("api", client.AllowedScopes);
        Assert.True(await db.ApiScopes.AnyAsync(s => s.Name == "openid"));
    }
}
