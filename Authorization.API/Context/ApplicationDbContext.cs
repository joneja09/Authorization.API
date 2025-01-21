
using Authorization.API.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.Context;
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // OAuth Clients
    public DbSet<Client> Clients { get; set; }

    // OAuth Authorization Codes
    public DbSet<AuthorizationCode> AuthorizationCodes { get; set; }

    // OAuth Refresh Tokens
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    // API Scopes
    public DbSet<ApiScope> ApiScopes { get; set; }

    // API Resources
    public DbSet<ApiResource> ApiResources { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure Identity Tables
        builder.Entity<ApplicationUser>()
            .ToTable("Users");

        builder.Entity<ApplicationRole>()
            .ToTable("Roles");

        // Configure OAuth Clients
        builder.Entity<Client>()
            .HasIndex(c => c.ClientId)
            .IsUnique();

        // Configure Authorization Codes
        builder.Entity<AuthorizationCode>()
            .HasIndex(ac => ac.Code)
            .IsUnique();  // Ensures each code is unique

        builder.Entity<AuthorizationCode>()
            .HasIndex(ac => new { ac.ClientId, ac.UserId });

        // Configure Refresh Tokens
        builder.Entity<RefreshToken>()
            .HasIndex(r => r.Token)
            .IsUnique();

        builder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithMany() // Each user can have many refresh tokens
            .HasForeignKey(rt => rt.UserId);

        // Configure API Scopes
        builder.Entity<ApiScope>()
            .HasIndex(s => s.Name)
            .IsUnique();
    }
}

