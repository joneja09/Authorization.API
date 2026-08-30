using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;

public class Client
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? Description { get; set; }

    [Required]
    public string ClientSecret { get; set; } = string.Empty;

    public string? RedirectUri { get; set; }

    public string? PostLogoutRedirectUri { get; set; }

    public bool RequirePkce { get; set; } = true;

    public bool AllowRefreshToken { get; set; } = true;

    public ICollection<string> AllowedScopes { get; set; } = new List<string>();
}
