using Authorization.API.Context;
using Authorization.API.Models;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.Services;

public interface IConsentService
{
    Task<bool> HasConsentAsync(string userId, string clientId, IEnumerable<string> requestedScopes, CancellationToken cancellationToken = default);
    Task GrantAsync(string userId, string clientId, IEnumerable<string> scopes, CancellationToken cancellationToken = default);
}

public class ConsentService : IConsentService
{
    private readonly ApplicationDbContext _db;

    public ConsentService(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<bool> HasConsentAsync(
        string userId,
        string clientId,
        IEnumerable<string> requestedScopes,
        CancellationToken cancellationToken = default)
    {
        var granted = await _db.UserConsents
            .AsNoTracking()
            .SingleOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId, cancellationToken);

        if (granted == null)
        {
            return false;
        }

        var grantedScopes = Split(granted.Scopes);
        return requestedScopes.All(scope => grantedScopes.Contains(scope));
    }

    public async Task GrantAsync(
        string userId,
        string clientId,
        IEnumerable<string> scopes,
        CancellationToken cancellationToken = default)
    {
        var existing = await _db.UserConsents
            .SingleOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId, cancellationToken);

        var scopeValue = string.Join(' ', scopes.Distinct(StringComparer.Ordinal));
        if (existing == null)
        {
            _db.UserConsents.Add(new UserConsent
            {
                UserId = userId,
                ClientId = clientId,
                Scopes = scopeValue,
                CreatedAt = DateTime.UtcNow
            });
        }
        else
        {
            existing.Scopes = scopeValue;
            existing.CreatedAt = DateTime.UtcNow;
        }

        await _db.SaveChangesAsync(cancellationToken);
    }

    public static List<string> Split(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return [];
        }

        return [.. scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    }

    public static bool IsRegisteredRedirect(Client client, string? redirectUri)
    {
        return !string.IsNullOrWhiteSpace(redirectUri)
            && Uri.TryCreate(redirectUri, UriKind.Absolute, out _)
            && string.Equals(client.RedirectUri, redirectUri, StringComparison.Ordinal);
    }

    public static bool TryResolveScopes(Client client, string? requested, out List<string> scopes)
    {
        var parsed = Split(requested);
        if (parsed.Count == 0)
        {
            scopes = client.AllowedScopes.ToList();
            return true;
        }

        if (parsed.Any(scope => !client.AllowedScopes.Contains(scope)))
        {
            scopes = [];
            return false;
        }

        scopes = parsed;
        return true;
    }
}
