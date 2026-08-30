using Authorization.API.Helpers;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Authorization.API.Controllers;

[Route("authorize")]
public class AuthorizeController : Controller
{
    private readonly IClientService _clientService;
    private readonly ITokenService _tokenService;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizeController(
        IClientService clientService,
        ITokenService tokenService,
        UserManager<ApplicationUser> userManager)
    {
        _clientService = clientService;
        _tokenService = tokenService;
        _userManager = userManager;
    }

    [HttpGet]
    [ApiExplorerSettings(IgnoreApi = true)]
    public async Task<IActionResult> Authorize(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method)
    {
        if (response_type != "code")
        {
            return BadRequest("Invalid response type. Only 'code' is supported.");
        }

        var client = await _clientService.GetClientById(client_id);
        if (client == null)
        {
            return BadRequest("Invalid client.");
        }

        if (string.IsNullOrWhiteSpace(redirect_uri)
            || !Uri.TryCreate(redirect_uri, UriKind.Absolute, out _)
            || !string.Equals(client.RedirectUri, redirect_uri, StringComparison.Ordinal))
        {
            return BadRequest("Invalid redirect URI.");
        }

        if (client.RequirePkce && string.IsNullOrWhiteSpace(code_challenge))
        {
            return RedirectWithError(redirect_uri, "invalid_request", "PKCE is required.", state);
        }

        if (!string.IsNullOrWhiteSpace(code_challenge)
            && !string.Equals(code_challenge_method, PkceHelper.S256, StringComparison.Ordinal))
        {
            return RedirectWithError(redirect_uri, "invalid_request", "Only S256 PKCE is supported.", state);
        }

        var cookieAuth = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!cookieAuth.Succeeded)
        {
            var challengeProperties = new AuthenticationProperties
            {
                RedirectUri = QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
                {
                    ["response_type"] = response_type,
                    ["client_id"] = client_id,
                    ["redirect_uri"] = redirect_uri,
                    ["scope"] = scope,
                    ["state"] = state,
                    ["code_challenge"] = code_challenge,
                    ["code_challenge_method"] = code_challenge_method
                })
            };

            return Challenge(challengeProperties, IdentityConstants.ApplicationScheme);
        }

        var user = await _userManager.GetUserAsync(cookieAuth.Principal);
        if (user == null)
        {
            return Unauthorized("User is not authenticated.");
        }

        var authorizationCode = await _tokenService.GenerateAuthorizationCode(
            client_id,
            user.Id,
            user.Id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method);

        var parameters = new Dictionary<string, string?>
        {
            ["code"] = authorizationCode
        };

        if (!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        return Redirect(QueryHelpers.AddQueryString(redirect_uri, parameters));
    }

    private IActionResult RedirectWithError(string redirectUri, string error, string description, string? state)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["error"] = error,
            ["error_description"] = description
        };

        if (!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        return Redirect(QueryHelpers.AddQueryString(redirectUri, parameters));
    }
}
