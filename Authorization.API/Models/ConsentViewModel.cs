using Authorization.API.Models;

namespace Authorization.API.Models;

public class ConsentViewModel
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string? Scope { get; set; }
    public string? State { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public IReadOnlyList<string> Scopes { get; set; } = [];
}

public sealed class RefreshTokenRotationResult
{
    public static RefreshTokenRotationResult Missing { get; } = new() { IsInvalid = true };
    public static RefreshTokenRotationResult Reused { get; } = new() { ReuseDetected = true, IsInvalid = true };

    public bool IsInvalid { get; init; }
    public bool ReuseDetected { get; init; }
    public ApplicationUser? User { get; init; }
    public string? UserId { get; init; }
    public string ClientId { get; init; } = string.Empty;
    public string FamilyId { get; init; } = string.Empty;
    public string NewRefreshToken { get; init; } = string.Empty;
}
