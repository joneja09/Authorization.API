using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;

public class AuthorizationCode
{
    [Key]
    public string Code { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? UserId { get; set; }

    public string Subject { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime ExpiresAt { get; set; }

    public bool IsUsed { get; set; }

    public string? RedirectUri { get; set; }

    public string? CodeChallenge { get; set; }

    public string? CodeChallengeMethod { get; set; }

    public string? Scopes { get; set; }
}
