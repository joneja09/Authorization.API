using Authorization.API.Context;
using Authorization.API.Helpers;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authorization.API.Controllers;

/// <summary>
/// The token controller.
/// </summary>
[ApiController]

public class TokenController : ControllerBase
{
    /// <summary>
    /// The context.
    /// </summary>
    private readonly ApplicationDbContext _context;
    /// <summary>
    /// The encryption service.
    /// </summary>
    private readonly EncryptionService _encryptionService;
    /// <summary>
    /// The token service.
    /// </summary>
    private readonly TokenService _tokenService;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenController"/> class.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="encryptionService">The encryption service.</param>
    /// <param name="tokenService">The token service.</param>
    public TokenController(ApplicationDbContext context, EncryptionService encryptionService, TokenService tokenService)
    {
        _context = context;
        _encryptionService = encryptionService;
        _tokenService = tokenService;
    }

    /// <summary>
    /// OAuth 2.0 Authorization Endpoint (Step 1)
    /// Client requests an authorization code with optional PKCE.
    /// </summary>

    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize(
    [FromQuery] string response_type,
    [FromQuery] string client_id,
    [FromQuery] string redirect_uri,
    [FromQuery] string? code_challenge,
    [FromQuery] string? code_challenge_method,
    [FromQuery] string state)
    {
        // Check if the user is authenticated (from cookies/session)
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(Authorize), new
                {
                    response_type,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    code_challenge_method,
                    state
                })
            });
        }

        // Extract authenticated user ID
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized("User is not authenticated");

        // Validate Client
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == client_id);
        if (client == null) return BadRequest("Invalid client");

        if (response_type != "code") return BadRequest("Invalid response type");
        if (client.RedirectUri != redirect_uri) return BadRequest("Invalid redirect URI");

        // Generate Authorization Code
        var authorizationCode = await _tokenService.GenerateAuthorizationCode(client_id, userId, code_challenge, code_challenge_method);

        // Redirect back to the client with the authorization code
        var redirectUrl = $"{redirect_uri}?code={authorizationCode}&state={state}";
        return Redirect(redirectUrl);
    }


    /// <summary>
    /// Exchanges the token.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns><![CDATA[Task<IActionResult>]]></returns>
    [HttpPost]
    [Route("token")]
    public async Task<IActionResult> ExchangeToken([FromForm] TokenRequest request)
    {
        switch (request.GrantType)
        {
            case "authorization_code":
                return await HandleAuthorizationCodeGrant(request);

            case "refresh_token":
                return await HandleRefreshTokenGrant(request);

            case "client_credentials":
                return await HandleClientCredentialsGrant(request);

            default:
                return BadRequest("Unsupported grant type.");
        }
    }

    /// <summary>
    /// Handle authorization code grant.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns><![CDATA[Task<IActionResult>]]></returns>
    private async Task<IActionResult> HandleAuthorizationCodeGrant(TokenRequest request)
    {
        // Validate client
        var client = await _context.Clients.SingleOrDefaultAsync(c => c.ClientId == request.ClientId);
        if (client == null || client.ClientSecret != request.ClientSecret)
            return Unauthorized("Invalid client credentials.");

        // Decrypt and validate authorization code
        var decryptedCode = _encryptionService.Decrypt(request.Code);
        var authCode = await _context.AuthorizationCodes
            .SingleOrDefaultAsync(c => c.Code == decryptedCode && c.ClientId == request.ClientId);

        if (authCode == null || authCode.ExpiresAt <= DateTime.UtcNow)
            return BadRequest("Invalid or expired authorization code.");

        if (!ValidatePkce(request.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
            return BadRequest("Invalid code verifier.");

        // Generate tokens
        // TODO: Look up user and pass it in
        var accessToken = _tokenService.GenerateAccessToken(authCode.Subject, authCode.ClientId);
        var refreshToken = GenerateRefreshToken();

        // Encrypt and store refresh token
        var encryptedRefreshToken = _encryptionService.Encrypt(refreshToken);
        await _tokenService.StoreRefreshToken(authCode.UserId, request.ClientId, encryptedRefreshToken);

        // Mark authorization code as used
        _context.AuthorizationCodes.Remove(authCode);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            access_token = accessToken,
            refresh_token = refreshToken,
            token_type = "Bearer",
            expires_in = 3600
        });
    }

    /// <summary>
    /// Handle refresh token grant.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns><![CDATA[Task<IActionResult>]]></returns>
    private async Task<IActionResult> HandleRefreshTokenGrant(TokenRequest request)
    {
        var encryptedToken = request.RefreshToken;

        // Decrypt and validate refresh token
        var refreshToken = _encryptionService.Decrypt(encryptedToken);
        var storedToken = await _context.RefreshTokens.Include(t => t.User).Include(t => t.Client)
            .SingleOrDefaultAsync(t => t.Token == encryptedToken && !t.IsRevoked);

        if (storedToken == null || storedToken.Expiry <= DateTime.UtcNow)
            return BadRequest("Invalid or expired refresh token.");

        // Generate new tokens
        var accessToken = _tokenService.GenerateAccessToken(storedToken.User.Email ?? storedToken.User.Id, storedToken.ClientId ?? "", null, storedToken.User);
        var newRefreshToken = GenerateRefreshToken();

        // Encrypt and store new refresh token, revoke the old one
        var encryptedNewToken = _encryptionService.Encrypt(newRefreshToken);
        storedToken.IsRevoked = true;

        await _tokenService.StoreRefreshToken(encryptedNewToken, storedToken.UserId, request.ClientId);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            access_token = accessToken,
            refresh_token = newRefreshToken,
            token_type = "Bearer",
            expires_in = 3600
        });
    }

    /// <summary>
    /// Handle client credentials grant.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns><![CDATA[Task<IActionResult>]]></returns>
    private async Task<IActionResult> HandleClientCredentialsGrant(TokenRequest request)
    {
        // Validate client credentials
        var client = await _context.Clients.SingleOrDefaultAsync(c => c.ClientId == request.ClientId);
        if (client == null || client.ClientSecret != request.ClientSecret)
        {
            return Unauthorized("Invalid client credentials.");
        }

        if (request.Scope != null && !client.AllowedScopes.Contains(request.Scope))
        {
            return BadRequest("Invalid scope.");
        }

        // Generate access token for the client
        var accessToken = _tokenService.GenerateJwtToken(client);

        return Ok(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600
        });
    }

    /// <summary>
    /// Generate refresh token.
    /// </summary>
    /// <returns>A string</returns>
    private string GenerateRefreshToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var tokenBytes = new byte[32];
        rng.GetBytes(tokenBytes);
        return Convert.ToBase64String(tokenBytes)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    /// <summary>
    /// Validate pkce.
    /// </summary>
    /// <param name="verifier">The verifier.</param>
    /// <param name="challenge">The challenge.</param>
    /// <param name="method">The method.</param>
    /// <returns>A bool</returns>
    private bool ValidatePkce(string verifier, string challenge, string method)
    {
        if (method == "S256")
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verifier));
            var hashBase64 = Convert.ToBase64String(hash)
                .Replace("+", "-").Replace("/", "_").TrimEnd('=');
            return hashBase64 == challenge;
        }
        return false;
    }
    

    //public async Task<string?> ExchangeAuthorizationCode(string code, string clientId, string? codeVerifier)
    //{
    //    var encryptedCode = _encryptionService.Encrypt(code);
    //    var authCode = await _context.AuthorizationCodes
    //        .FirstOrDefaultAsync(c => c.Code == encryptedCode && c.ClientId == clientId);

    //    if (authCode == null || authCode.Expiration < DateTime.UtcNow)
    //        return null; // Invalid or expired authorization code

    //    // Validate PKCE (if required)
    //    if (!string.IsNullOrEmpty(authCode.CodeChallenge))
    //    {
    //        if (string.IsNullOrEmpty(codeVerifier))
    //            return null; // PKCE is required, but no verifier was provided

    //        var expectedChallenge = PkceHelper.ComputeCodeChallenge(codeVerifier, authCode.CodeChallengeMethod);

    //        if (expectedChallenge != authCode.CodeChallenge)
    //            return null; // PKCE validation failed
    //    }

    //    // Remove used authorization code (one-time use)
    //    _context.AuthorizationCodes.Remove(authCode);
    //    await _context.SaveChangesAsync();

    //    // Generate and return access token
    //    return _tokenService.GenerateAccessToken(authCode.UserId, clientId);
    //}

    /// <summary>
    /// Exchanges authorization code.
    /// </summary>
    /// <param name="authorizationCode">The authorization code.</param>
    /// <param name="clientId">The client id.</param>
    /// <param name="codeVerifier">The code verifier.</param>
    /// <exception cref="InvalidOperationException"></exception>
    /// <returns><![CDATA[Task<TokenResponse>]]></returns>
    public async Task<TokenResponse> ExchangeAuthorizationCode(string authorizationCode, string clientId, string codeVerifier)
    {
        // Retrieve the authorization code from the database
        var authCodeEntity = await _context.AuthorizationCodes
            .FirstOrDefaultAsync(ac => ac.Code == authorizationCode && ac.ClientId == clientId);

        if (authCodeEntity == null || authCodeEntity.IsUsed || authCodeEntity.ExpiresAt < DateTime.UtcNow)
        {
            throw new InvalidOperationException("Invalid or expired authorization code.");
        }

        // Verify PKCE (Proof Key for Code Exchange) if a code challenge was used
        if (!string.IsNullOrEmpty(authCodeEntity.CodeChallenge))
        {
            string computedChallenge = PkceHelper.ComputeCodeChallenge(codeVerifier, authCodeEntity.CodeChallengeMethod);
            if (authCodeEntity.CodeChallenge != computedChallenge)
            {
                throw new InvalidOperationException("Invalid code verifier.");
            }
        }

        // Mark the authorization code as used (to prevent reuse)
        authCodeEntity.IsUsed = true;
        await _context.SaveChangesAsync();

        // Generate access and refresh tokens
        string accessToken = _tokenService.GenerateAccessToken(authCodeEntity.Subject, clientId);
        string refreshToken = _tokenService.GenerateRefreshToken();

        // Store the refresh token in the database
        await _tokenService.StoreRefreshToken(refreshToken, authCodeEntity.UserId, clientId);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = _tokenService.GetAccessTokenExpiry(),
            TokenType = "Bearer"
        };
    }

}
