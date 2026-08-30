using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;

public class RefreshToken
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string Token { get; set; } = string.Empty;

    public string? UserId { get; set; }

    public string? ClientId { get; set; }

    public DateTime Expiry { get; set; }

    public bool IsRevoked { get; set; }

    public string FamilyId { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime Created { get; set; } = DateTime.UtcNow;

    public ApplicationUser? User { get; set; }

    public Client? Client { get; set; }
}
