using Authorization.API.Context;
using Authorization.API.Helpers;
using Authorization.API.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authorization.API.Services;

/// <summary>
/// The token service interface.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Generate authorization code.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="codeChallenge">The code challenge.</param>
    /// <param name="codeChallengeMethod">The code challenge method.</param>
    /// <returns><![CDATA[Task<string>]]></returns>
    Task<string> GenerateAuthorizationCode(string clientId, string userId, string? codeChallenge, string? codeChallengeMethod);

    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns>A string</returns>
    string GenerateJwtToken(ApplicationUser user);

    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <returns>A string</returns>
    string GenerateJwtToken(Client client);

    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <param name="userId">The user id.</param>
    /// <returns>A string</returns>
    string GenerateJwtToken(string clientId, string? userId);

    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="claims">The claims.</param>
    /// <param name="expiresAt">The expires at.</param>
    /// <returns>A string</returns>
    string GenerateJwtToken(List<Claim> claims, DateTime? expiresAt = null);

    /// <summary>
    /// Generate refresh token.
    /// </summary>
    /// <returns>A string</returns>
    string GenerateRefreshToken();

    /// <summary>
    /// Store refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="clientId">The client id.</param>
    /// <returns>A Task</returns>
    Task StoreRefreshToken(string refreshToken, string? userId = null, string? clientId = null);

    /// <summary>
    /// Validate refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="clientId">The client id.</param>
    /// <returns><![CDATA[Task<bool>]]></returns>
    Task<bool> ValidateRefreshToken(string refreshToken, string? userId = null, string? clientId = null);

    /// <summary>
    /// Revokes refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="clientId">The client id.</param>
    /// <returns>A Task</returns>
    Task RevokeRefreshToken(string refreshToken, string? userId = null, string? clientId = null);

    /// <summary>
    /// Revokes user refresh tokens.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <returns>A Task</returns>
    Task RevokeUserRefreshTokens(string userId);

    /// <summary>
    /// Revokes client refresh tokens.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <returns>A Task</returns>
    Task RevokeClientRefreshTokens(string clientId);

    /// <summary>
    /// Validate the token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <returns>A ClaimsPrincipal?</returns>
    ClaimsPrincipal? ValidateToken(string token);
}

/// <summary>
/// The token service.
/// </summary>
public class TokenService : ITokenService
{
    /// <summary>
    /// The config.
    /// </summary>
    private readonly IConfiguration _config;
    /// <summary>
    /// The db context.
    /// </summary>
    private readonly ApplicationDbContext _dbContext;
    /// <summary>
    /// The encryption service.
    /// </summary>
    private readonly IEncryptionService _encryptionService;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenService"/> class.
    /// </summary>
    /// <param name="config">The config.</param>
    /// <param name="context">The context.</param>
    public TokenService(IConfiguration config, ApplicationDbContext context, IEncryptionService encryptionService)
    {
        _config = config;
        _dbContext = context;
        _encryptionService = encryptionService;
    }

    /// <summary>
    /// Generate authorization code.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="codeChallenge">The code challenge.</param>
    /// <param name="codeChallengeMethod">The code challenge method.</param>
    /// <returns><![CDATA[Task<string>]]></returns>
    public async Task<string> GenerateAuthorizationCode(string clientId, string userId, string? codeChallenge, string? codeChallengeMethod)
    {
        var code = TokenHelper.GenerateSecureCode(); // Generate a random secure code
        var encryptedCode = _encryptionService.Encrypt(code);

        var authCode = new AuthorizationCode
        {
            Code = encryptedCode,
            ClientId = clientId,
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            CodeChallenge = codeChallenge, // Store PKCE challenge
            CodeChallengeMethod = codeChallengeMethod // Store PKCE method
        };

        _dbContext.AuthorizationCodes.Add(authCode);
        await _dbContext.SaveChangesAsync();

        return code;
    }

    public string GenerateAccessToken(string subject, string clientId, List<string>? scopes = null, ApplicationUser? user = null)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, subject),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim("client_id", clientId)
        };

        if (user != null)
        {
            claims.Add(new(ClaimTypes.NameIdentifier, user.Id));
            claims.Add(new(ClaimTypes.Name, user.UserName ?? ""));
            claims.Add(new(ClaimTypes.Email, user.Email ?? ""));
        }

        // Add scopes as claims if provided
        if (scopes != null)
        {
            claims.Add(new Claim("scope", string.Join(" ", scopes)));
        }

        return GenerateJwtToken(claims);
    }

    public int GetAccessTokenExpiry()
    {
        var expiry = _config["Jwt:AccessTokenExpiryMinutes"];

        if (int.TryParse(expiry, out var result))
        {
            return result * 60; // Convert minutes to seconds
        }

        return 2400; // Convert minutes to seconds
    }


    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns>A string</returns>
    public string GenerateJwtToken(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new (ClaimTypes.NameIdentifier, user.Id),
            new (ClaimTypes.Name, user.UserName ?? ""),
            new (ClaimTypes.Email, user.Email ?? "")
        };

        return GenerateJwtToken(claims);
    }

    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <returns>A string</returns>
    public string GenerateJwtToken(Client client)
    {
        var claims = new List<Claim>
        {
            new (ClaimTypes.NameIdentifier, client.ClientId),
            new (ClaimTypes.Name, client.ClientId ?? ""),
            new ("client_id", client.ClientId ?? "")
        };

        return GenerateJwtToken(claims);
    }

    /// <summary>
    /// Generates a JWT access token for the given user or client.
    /// </summary>
    public string GenerateJwtToken(string clientId, string? userId)
    {
        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new ("client_id", clientId)
        };

        if (!string.IsNullOrEmpty(userId))
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
        }

        return GenerateJwtToken(claims);
    }

    /// <summary>
    /// Generate jwt token.
    /// </summary>
    /// <param name="claims">The claims.</param>
    /// <param name="expiresAt">The expires at.</param>
    /// <returns>A string</returns>
    public string GenerateJwtToken(List<Claim> claims, DateTime? expiresAt = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: expiresAt ?? DateTime.UtcNow.AddMinutes(60),
            signingCredentials: credentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // Generate a new refresh token (this is the token you'll issue)
    /// <summary>
    /// Generate refresh token.
    /// </summary>
    /// <returns>A string</returns>
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();

        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    // Store the refresh token in the database
    /// <summary>
    /// Store refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="clientId">The client id.</param>
    /// <exception cref="ArgumentException"></exception>
    /// <returns>A Task</returns>
    public async Task StoreRefreshToken(string refreshToken, string? userId = null, string? clientId = null)
    {
        // Ensure that only one of userId or clientId is set
        if (userId == null && clientId == null)
        {
            throw new ArgumentException("Either userId or clientId must be provided");
        }

        if (userId != null && clientId != null)
        {
            throw new ArgumentException("Only one of userId or clientId should be provided");
        }

        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            Expiry = DateTime.UtcNow.AddDays(30), // Refresh token expiration (adjust as necessary)
            IsRevoked = false,
        };

        // Store the refresh token for a user
        if (userId != null)
        {
            refreshTokenEntity.UserId = userId;
        }

        // Store the refresh token for a client
        if (clientId != null)
        {
            refreshTokenEntity.ClientId = clientId;
        }

        // Add to database
        await _dbContext.RefreshTokens.AddAsync(refreshTokenEntity);
        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// Revokes refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="clientId">The client id.</param>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    /// <returns>A Task</returns>
    public async Task RevokeRefreshToken(string refreshToken, string? userId = null, string? clientId = null)
    {
        // Ensure that only one of userId or clientId is provided
        if (userId == null && clientId == null)
        {
            throw new ArgumentException("Either userId or clientId must be provided");
        }

        if (userId != null && clientId != null)
        {
            throw new ArgumentException("Only one of userId or clientId should be provided");
        }

        // Find the refresh token in the database
        var refreshTokenQuery = _dbContext.RefreshTokens.Where(rt => rt.Token == refreshToken);
            
        var refreshTokenEntity = await (userId == null
            ? refreshTokenQuery.FirstOrDefaultAsync(rt => rt.ClientId == clientId)
            : refreshTokenQuery.FirstOrDefaultAsync(rt => rt.UserId == userId));
        
        if (refreshTokenEntity == null)
        {
            throw new InvalidOperationException("Refresh token not found or does not belong to the specified user or client");
        }

        // Mark the token as revoked
        refreshTokenEntity.IsRevoked = true;

        // Save changes to the database
        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// Revokes user refresh tokens.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <returns>A Task</returns>
    public async Task RevokeUserRefreshTokens(string userId)
    {
        var refreshTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId)
            .ToListAsync();

        foreach (var refreshToken in refreshTokens)
        {
            refreshToken.IsRevoked = true;
        }

        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// Revokes client refresh tokens.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <returns>A Task</returns>
    public async Task RevokeClientRefreshTokens(string clientId)
    {
        var refreshTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.ClientId == clientId)
            .ToListAsync();

        foreach (var refreshToken in refreshTokens)
        {
            refreshToken.IsRevoked = true;
        }

        await _dbContext.SaveChangesAsync();
    }

    // Validate if the refresh token is still valid
    /// <summary>
    /// Validate refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="userId">The user id.</param>
    /// <param name="clientId">The client id.</param>
    /// <returns><![CDATA[Task<bool>]]></returns>
    public async Task<bool> ValidateRefreshToken(string refreshToken, string? userId = null, string? clientId = null)
    {
        var refreshTokenEntity = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && !rt.IsRevoked && rt.Expiry > DateTime.UtcNow);

        // Validate User-based refresh token
        if (userId != null && refreshTokenEntity != null && refreshTokenEntity.UserId == userId)
        {
            return refreshTokenEntity.Expiry > DateTime.UtcNow;
        }

        // Validate Client-based refresh token
        if (clientId != null && refreshTokenEntity != null && refreshTokenEntity.ClientId == clientId)
        {
            return refreshTokenEntity.Expiry > DateTime.UtcNow;
        }

        return false;
    }


    /// <summary>
    /// Validates a JWT token and returns the claims principal.
    /// </summary>
    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch
        {
            return null; // Token is invalid or expired
        }
    }
}
