namespace Authorization.API.Models;

public class RefreshTokenRequest
{
    public string? UserId { get; set; }
    public string? ClientId { get; set; }
    public string RefreshToken { get; set; }
}
