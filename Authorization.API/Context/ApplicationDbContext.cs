
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

    public DbSet<Client> Clients { get; set; }

    public DbSet<AuthorizationCode> AuthorizationCodes { get; set; }

    public DbSet<RefreshToken> RefreshTokens { get; set; }

    public DbSet<ApiScope> ApiScopes { get; set; }

    public DbSet<ApiResource> ApiResources { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>()
            .ToTable("Users");

        builder.Entity<ApplicationRole>()
            .ToTable("Roles");

        builder.Entity<Client>()
            .HasIndex(c => c.ClientId)
            .IsUnique();

        builder.Entity<AuthorizationCode>()
            .HasIndex(ac => ac.Code)
            .IsUnique();

        builder.Entity<AuthorizationCode>()
            .HasIndex(ac => new { ac.ClientId, ac.UserId });

        builder.Entity<RefreshToken>()
            .HasIndex(r => r.Token)
            .IsUnique();

        builder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithMany()
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Entity<RefreshToken>()
            .HasOne(rt => rt.Client)
            .WithMany()
            .HasPrincipalKey(c => c.ClientId)
            .HasForeignKey(rt => rt.ClientId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Entity<ApiScope>()
            .HasIndex(s => s.Name)
            .IsUnique();
    }
}
