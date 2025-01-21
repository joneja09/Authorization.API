namespace Authorization.API.Models;

public class AuthorizationRequest
{
    public string ClientId { get; set; }
    public string RedirectUri { get; set; }
    public string CodeChallenge { get; set; }
}
