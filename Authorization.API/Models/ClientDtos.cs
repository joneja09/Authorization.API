using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;

public class ClientCreateRequest
{
    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? Description { get; set; }

    public string? ClientSecret { get; set; }

    public string? RedirectUri { get; set; }

    public string? PostLogoutRedirectUri { get; set; }

    public bool RequirePkce { get; set; } = true;

    public bool AllowRefreshToken { get; set; } = true;

    public List<string> AllowedScopes { get; set; } = [];
}

public class ClientUpdateRequest
{
    public string? Description { get; set; }

    public string? RedirectUri { get; set; }

    public string? PostLogoutRedirectUri { get; set; }

    public bool? RequirePkce { get; set; }

    public bool? AllowRefreshToken { get; set; }

    public List<string>? AllowedScopes { get; set; }
}

public class ClientResponse
{
    public string ClientId { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? RedirectUri { get; set; }
    public string? PostLogoutRedirectUri { get; set; }
    public bool RequirePkce { get; set; }
    public bool AllowRefreshToken { get; set; }
    public IReadOnlyList<string> AllowedScopes { get; set; } = [];

    public static ClientResponse From(Client client) => new()
    {
        ClientId = client.ClientId,
        Description = client.Description,
        RedirectUri = client.RedirectUri,
        PostLogoutRedirectUri = client.PostLogoutRedirectUri,
        RequirePkce = client.RequirePkce,
        AllowRefreshToken = client.AllowRefreshToken,
        AllowedScopes = client.AllowedScopes.ToList()
    };
}

public class ClientCreatedResponse : ClientResponse
{
    public string ClientSecret { get; set; } = string.Empty;
}
