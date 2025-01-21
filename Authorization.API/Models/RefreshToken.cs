using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;

public class RefreshToken
{
    [Key]
    public int Id { get; set; }
    public string Token { get; set; } // Store the encrypted refresh token
    public string? UserId { get; set; }
    public string? ClientId { get; set; }
    public DateTime Expiry { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime Created { get; set; } // Creation timestamp
    public ApplicationUser User { get; set; } // Navigation property to user
    public Client Client { get; set; } // For client tokens
}
