using System.ComponentModel.DataAnnotations;

namespace Authorization.API.Models;
/// <summary>
/// The client.
/// </summary>
public class Client
{
    /// <summary>
    /// Gets or sets the id.
    /// </summary>
    /// <value>An int</value>
    [Key]
    public int Id { get; set; }
    /// <summary>
    /// Gets or sets the client id.
    /// </summary>
    /// <value>A string</value>
    public string ClientId { get; set; }
    /// <summary>
    /// Gets or sets the description.
    /// </summary>
    /// <value>A string</value>
    public string Description { get; set; }
    /// <summary>
    /// Gets or sets the client secret.
    /// </summary>
    /// <value>A string</value>
    public string ClientSecret { get; set; }
    /// <summary>
    /// Gets or sets the redirect uri.
    /// </summary>
    /// <value>A string</value>
    public string? RedirectUri { get; set; }
    /// <summary>
    /// Gets or sets the post logout redirect uri.
    /// </summary>
    /// <value>A string</value>
    public string? PostLogoutRedirectUri { get; set; }
    /// <summary>
    /// Gets or sets  a value indicating whether to require pkce.
    /// </summary>
    /// <value>A bool</value>
    public bool RequirePkce { get; set; }
    /// <summary>
    /// Gets or sets a value indicating whether allow refresh token.
    /// </summary>
    /// <value>A bool</value>
    public bool AllowRefreshToken { get; set; }
    /// <summary>
    /// Gets or sets the allowed scopes.
    /// </summary>
    /// <value>A collection of strings.</value>
    public ICollection<string> AllowedScopes { get; set; }
}
