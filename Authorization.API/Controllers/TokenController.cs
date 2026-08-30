using Authorization.API.Context;
using Authorization.API.Helpers;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.Controllers;

[ApiController]
[Route("token")]
public class TokenController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ITokenService _tokenService;

    public TokenController(ApplicationDbContext context, ITokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> ExchangeToken([FromForm] TokenRequest request)
    {
        return request.GrantType switch
        {
            "authorization_code" => await HandleAuthorizationCodeGrant(request),
            "refresh_token" => await HandleRefreshTokenGrant(request),
            "client_credentials" => await HandleClientCredentialsGrant(request),
            _ => BadRequest(new { error = "unsupported_grant_type" })
        };
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrant(TokenRequest request)
    {
        var client = await ValidateClientAsync(request);
        if (client is null)
        {
            return Unauthorized(new { error = "invalid_client" });
        }

        if (string.IsNullOrWhiteSpace(request.Code))
        {
            return BadRequest(new { error = "invalid_request", error_description = "code is required." });
        }

        var hashedCode = TokenHelper.HashToken(request.Code);
        var authCode = await _context.AuthorizationCodes
            .SingleOrDefaultAsync(c => c.Code == hashedCode && c.ClientId == request.ClientId);

        if (authCode == null || authCode.IsUsed || authCode.ExpiresAt <= DateTime.UtcNow)
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Invalid or expired authorization code." });
        }

        if (!string.Equals(authCode.RedirectUri, request.RedirectUri, StringComparison.Ordinal))
        {
            return BadRequest(new { error = "invalid_grant", error_description = "redirect_uri mismatch." });
        }

        if (client.RequirePkce || !string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (!PkceHelper.Validate(request.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
            {
                return BadRequest(new { error = "invalid_grant", error_description = "Invalid code verifier." });
            }
        }

        authCode.IsUsed = true;
        await _context.SaveChangesAsync();

        ApplicationUser? user = null;
        if (!string.IsNullOrEmpty(authCode.UserId))
        {
            user = await _context.Users.FindAsync(authCode.UserId);
        }

        var scopes = SplitScopes(authCode.Scopes);
        var accessToken = _tokenService.GenerateAccessToken(authCode.Subject, authCode.ClientId, scopes, user);
        string? refreshToken = null;

        if (client.AllowRefreshToken)
        {
            refreshToken = _tokenService.GenerateRefreshToken();
            await _tokenService.StoreRefreshToken(refreshToken, authCode.UserId, request.ClientId);
        }

        _context.AuthorizationCodes.Remove(authCode);
        await _context.SaveChangesAsync();

        return Ok(CreateTokenResponse(accessToken, refreshToken));
    }

    private async Task<IActionResult> HandleRefreshTokenGrant(TokenRequest request)
    {
        var client = await ValidateClientAsync(request);
        if (client is null)
        {
            return Unauthorized(new { error = "invalid_client" });
        }

        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest(new { error = "invalid_request", error_description = "refresh_token is required." });
        }

        var hashedToken = TokenHelper.HashToken(request.RefreshToken);
        var storedToken = await _context.RefreshTokens
            .Include(t => t.User)
            .SingleOrDefaultAsync(t => t.Token == hashedToken && t.ClientId == request.ClientId && !t.IsRevoked);

        if (storedToken == null || storedToken.Expiry <= DateTime.UtcNow)
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Invalid or expired refresh token." });
        }

        storedToken.IsRevoked = true;

        var scopes = request.Scope is null ? null : SplitScopes(request.Scope);
        var subject = storedToken.User?.Id ?? storedToken.UserId ?? storedToken.ClientId ?? request.ClientId;
        var accessToken = _tokenService.GenerateAccessToken(subject, storedToken.ClientId ?? request.ClientId, scopes, storedToken.User);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        await _tokenService.StoreRefreshToken(newRefreshToken, storedToken.UserId, request.ClientId);
        await _context.SaveChangesAsync();

        return Ok(CreateTokenResponse(accessToken, newRefreshToken));
    }

    private async Task<IActionResult> HandleClientCredentialsGrant(TokenRequest request)
    {
        var client = await ValidateClientAsync(request);
        if (client is null)
        {
            return Unauthorized(new { error = "invalid_client" });
        }

        IEnumerable<string>? scopes = null;
        if (!string.IsNullOrWhiteSpace(request.Scope))
        {
            var requested = SplitScopes(request.Scope);
            if (requested.Any(scope => !client.AllowedScopes.Contains(scope)))
            {
                return BadRequest(new { error = "invalid_scope" });
            }

            scopes = requested;
        }

        var accessToken = scopes == null
            ? _tokenService.GenerateJwtToken(client)
            : _tokenService.GenerateAccessToken(client.ClientId, client.ClientId, scopes);

        return Ok(CreateTokenResponse(accessToken));
    }

    private async Task<Client?> ValidateClientAsync(TokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            return null;
        }

        var client = await _context.Clients.SingleOrDefaultAsync(c => c.ClientId == request.ClientId);
        if (client == null || !TokenHelper.SecretsEqual(client.ClientSecret, request.ClientSecret))
        {
            return null;
        }

        return client;
    }

    private TokenResponse CreateTokenResponse(string accessToken, string? refreshToken = null)
    {
        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = _tokenService.GetAccessTokenExpirySeconds()
        };
    }

    private static List<string> SplitScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return [];
        }

        return [.. scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    }
}
