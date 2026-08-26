using Authorization.API.Context;
using Authorization.API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Authorization.API.Data;

public static class DatabaseInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var provider = scope.ServiceProvider;
        var config = provider.GetRequiredService<IConfiguration>();
        var logger = provider.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(DatabaseInitializer));

        var migrateOnStartup = config.GetValue("Database:MigrateOnStartup", false);
        if (!migrateOnStartup)
        {
            return;
        }

        var db = provider.GetRequiredService<ApplicationDbContext>();
        await WaitAndMigrateAsync(db, logger, cancellationToken);

        var seedOptions = provider.GetRequiredService<IOptions<SeedOptions>>().Value;
        if (!seedOptions.Enabled)
        {
            return;
        }

        await SeedAsync(provider, seedOptions, logger, cancellationToken);
    }

    public static async Task WaitAndMigrateAsync(
        ApplicationDbContext db,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        var delaysSeconds = new[] { 2, 3, 5, 8, 8, 8, 8, 8, 8, 8 };

        for (var attempt = 0; attempt < delaysSeconds.Length; attempt++)
        {
            try
            {
                if (db.Database.IsRelational())
                {
                    if (db.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
                    {
                        await db.Database.EnsureCreatedAsync(cancellationToken);
                    }
                    else
                    {
                        await db.Database.MigrateAsync(cancellationToken);
                    }
                }
                else
                {
                    await db.Database.EnsureCreatedAsync(cancellationToken);
                }

                logger.LogInformation("Database is ready.");
                return;
            }
            catch (Exception ex) when (attempt < delaysSeconds.Length - 1 && !cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(
                    ex,
                    "Database is not ready (attempt {Attempt}/{Total}). Retrying in {Delay}s.",
                    attempt + 1,
                    delaysSeconds.Length,
                    delaysSeconds[attempt]);
                await Task.Delay(TimeSpan.FromSeconds(delaysSeconds[attempt]), cancellationToken);
            }
        }
    }

    public static async Task SeedAsync(
        IServiceProvider services,
        SeedOptions options,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var db = services.GetRequiredService<ApplicationDbContext>();

        foreach (var roleName in new[] { "Administrator", "User" })
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new ApplicationRole(roleName));
            }
        }

        await EnsureUserAsync(userManager, options.AdminEmail, options.AdminPassword, "Administrator");
        await EnsureUserAsync(userManager, options.DemoUserEmail, options.DemoUserPassword, "User");

        foreach (var (name, description) in new[]
        {
            ("openid", "OpenID"),
            ("profile", "User profile"),
            ("email", "Email address"),
            ("api", "API access")
        })
        {
            if (!await db.ApiScopes.AnyAsync(s => s.Name == name, cancellationToken))
            {
                db.ApiScopes.Add(new ApiScope { Name = name, Description = description });
            }
        }

        if (!await db.Clients.AnyAsync(c => c.ClientId == options.DemoClientId, cancellationToken))
        {
            db.Clients.Add(new Client
            {
                ClientId = options.DemoClientId,
                Description = "Local demo confidential client",
                ClientSecret = options.DemoClientSecret,
                RedirectUri = options.DemoRedirectUri,
                RequirePkce = true,
                AllowRefreshToken = true,
                AllowedScopes = ["openid", "profile", "email", "api"]
            });
        }

        await db.SaveChangesAsync(cancellationToken);
        logger.LogInformation("Development seed data is in place.");
    }

    private static async Task EnsureUserAsync(
        UserManager<ApplicationUser> userManager,
        string email,
        string password,
        string role)
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to seed user {email}: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }

        if (!await userManager.IsInRoleAsync(user, role))
        {
            await userManager.AddToRoleAsync(user, role);
        }
    }
}
