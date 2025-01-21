using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;

public class AuthorizationCode
{
    [Key]
    public string Code { get; set; }  // The actual authorization code (should be securely generated)

    [Required]
    public string ClientId { get; set; }  // The client that requested authorization

    public string? UserId { get; set; }  // The user who authorized the request

    public string Subject { get; set; } // The identifier of the user.  Allows for anonymous users.

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;  // Timestamp when issued

    public DateTime ExpiresAt { get; set; }  // Expiration time of the authorization code

    public bool IsUsed { get; set; } = false;  // Ensures the code is only used once

    public string RedirectUri { get; set; }  // The redirect URI used during authorization

    public string CodeChallenge { get; set; }  // PKCE Challenge (if applicable)

    public string CodeChallengeMethod { get; set; }  // PKCE Method (e.g., S256)

    public string Scopes { get; set; }  // Space-separated list of scopes granted
}

