using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Authorization.API.Controllers;

[Route("consent")]
public class ConsentController : Controller
{
    private readonly IClientService _clients;
    private readonly IConsentService _consents;
    private readonly UserManager<ApplicationUser> _userManager;

    public ConsentController(
        IClientService clients,
        IConsentService consents,
        UserManager<ApplicationUser> userManager)
    {
        _clients = clients;
        _consents = consents;
        _userManager = userManager;
    }

    [HttpGet]
    [ApiExplorerSettings(IgnoreApi = true)]
    public async Task<IActionResult> Index(
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method)
    {
        var auth = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!auth.Succeeded)
        {
            return Challenge(IdentityConstants.ApplicationScheme);
        }

        var client = await _clients.GetClientById(client_id);
        if (client == null)
        {
            return BadRequest("Invalid client.");
        }

        var scopes = ConsentService.Split(scope);
        if (scopes.Count == 0)
        {
            scopes = client.AllowedScopes.ToList();
        }

        return View(new ConsentViewModel
        {
            ClientId = client.ClientId,
            ClientName = client.Description ?? client.ClientId,
            RedirectUri = redirect_uri,
            Scope = string.Join(' ', scopes),
            State = state,
            CodeChallenge = code_challenge,
            CodeChallengeMethod = code_challenge_method,
            Scopes = scopes
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [ApiExplorerSettings(IgnoreApi = true)]
    public async Task<IActionResult> Index(
        string clientId,
        string redirectUri,
        string? scope,
        string? state,
        string? codeChallenge,
        string? codeChallengeMethod,
        string decision)
    {
        var auth = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!auth.Succeeded)
        {
            return Challenge(IdentityConstants.ApplicationScheme);
        }

        var user = await _userManager.GetUserAsync(auth.Principal);
        if (user == null)
        {
            return Unauthorized();
        }

        if (string.Equals(decision, "deny", StringComparison.OrdinalIgnoreCase))
        {
            return Redirect(QueryHelpers.AddQueryString(redirectUri, new Dictionary<string, string?>
            {
                ["error"] = "access_denied",
                ["state"] = state
            }));
        }

        var scopes = ConsentService.Split(scope);
        await _consents.GrantAsync(user.Id, clientId, scopes);

        return Redirect(QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = codeChallengeMethod
        }));
    }
}
