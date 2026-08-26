using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authorization.API.Context;
using Authorization.API.Helpers;
using Authorization.API.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Authorization.API.Services;

public interface ITokenService
{
    Task<string> GenerateAuthorizationCode(
        string clientId,
        string userId,
        string subject,
        string? redirectUri,
        string? scopes,
        string? codeChallenge,
        string? codeChallengeMethod);

    string GenerateAccessToken(string subject, string clientId, IEnumerable<string>? scopes = null, ApplicationUser? user = null, IEnumerable<string>? roles = null);

    string GenerateJwtToken(ApplicationUser user, IEnumerable<string>? roles = null);

    string GenerateJwtToken(Client client);

    string GenerateJwtToken(string clientId, string? userId);

    string GenerateJwtToken(List<Claim> claims, DateTime? expiresAt = null);

    string GenerateRefreshToken();

    int GetAccessTokenExpirySeconds();

    Task StoreRefreshToken(string refreshToken, string? userId = null, string? clientId = null);

    Task<bool> ValidateRefreshToken(string refreshToken, string? userId = null, string? clientId = null);

    Task RevokeRefreshToken(string refreshToken, string? userId = null, string? clientId = null);

    Task RevokeUserRefreshTokens(string userId);

    Task RevokeClientRefreshTokens(string clientId);

    ClaimsPrincipal? ValidateToken(string token);
}

public class TokenService : ITokenService
{
    private readonly IConfiguration _config;
    private readonly ApplicationDbContext _dbContext;

    public TokenService(IConfiguration config, ApplicationDbContext context)
    {
        _config = config;
        _dbContext = context;
    }

    public async Task<string> GenerateAuthorizationCode(
        string clientId,
        string userId,
        string subject,
        string? redirectUri,
        string? scopes,
        string? codeChallenge,
        string? codeChallengeMethod)
    {
        var code = TokenHelper.GenerateSecureCode();

        var authCode = new AuthorizationCode
        {
            Code = TokenHelper.HashToken(code),
            ClientId = clientId,
            UserId = userId,
            Subject = subject,
            RedirectUri = redirectUri,
            Scopes = scopes,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod
        };

        _dbContext.AuthorizationCodes.Add(authCode);
        await _dbContext.SaveChangesAsync();

        return code;
    }

    public string GenerateAccessToken(string subject, string clientId, IEnumerable<string>? scopes = null, ApplicationUser? user = null, IEnumerable<string>? roles = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("client_id", clientId)
        };

        if (user != null)
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
            claims.Add(new Claim(ClaimTypes.Name, user.UserName ?? string.Empty));
            if (!string.IsNullOrEmpty(user.Email))
            {
                claims.Add(new Claim(ClaimTypes.Email, user.Email));
            }
        }

        AddRoleClaims(claims, roles);

        if (scopes != null)
        {
            var scopeValue = string.Join(' ', scopes);
            if (!string.IsNullOrWhiteSpace(scopeValue))
            {
                claims.Add(new Claim("scope", scopeValue));
            }
        }

        return GenerateJwtToken(claims);
    }

    public int GetAccessTokenExpirySeconds()
    {
        var expiry = _config["Jwt:AccessTokenExpiryMinutes"];
        if (int.TryParse(expiry, out var minutes) && minutes > 0)
        {
            return minutes * 60;
        }

        return 30 * 60;
    }

    public string GenerateJwtToken(ApplicationUser user, IEnumerable<string>? roles = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.UserName ?? string.Empty),
            new(JwtRegisteredClaimNames.Sub, user.Id)
        };

        if (!string.IsNullOrEmpty(user.Email))
        {
            claims.Add(new Claim(ClaimTypes.Email, user.Email));
        }

        AddRoleClaims(claims, roles);

        return GenerateJwtToken(claims);
    }

    public string GenerateJwtToken(Client client)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, client.ClientId),
            new(ClaimTypes.Name, client.ClientId),
            new(JwtRegisteredClaimNames.Sub, client.ClientId),
            new("client_id", client.ClientId)
        };

        if (client.AllowedScopes.Count > 0)
        {
            claims.Add(new Claim("scope", string.Join(' ', client.AllowedScopes)));
        }

        return GenerateJwtToken(claims);
    }

    public string GenerateJwtToken(string clientId, string? userId)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId)
        };

        if (!string.IsNullOrEmpty(userId))
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userId));
        }

        return GenerateJwtToken(claims);
    }

    public string GenerateJwtToken(List<Claim> claims, DateTime? expiresAt = null)
    {
        var secret = _config["Jwt:SecretKey"]
            ?? throw new InvalidOperationException("Jwt:SecretKey is missing.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: expiresAt ?? DateTime.UtcNow.AddSeconds(GetAccessTokenExpirySeconds()),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        return TokenHelper.GenerateSecureCode(64);
    }

    public async Task StoreRefreshToken(string refreshToken, string? userId = null, string? clientId = null)
    {
        if (string.IsNullOrWhiteSpace(userId) && string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("Either userId or clientId must be provided.");
        }

        var refreshTokenEntity = new RefreshToken
        {
            Token = TokenHelper.HashToken(refreshToken),
            Expiry = DateTime.UtcNow.AddDays(30),
            IsRevoked = false,
            Created = DateTime.UtcNow,
            UserId = userId,
            ClientId = clientId
        };

        await _dbContext.RefreshTokens.AddAsync(refreshTokenEntity);
        await _dbContext.SaveChangesAsync();
    }

    public async Task RevokeRefreshToken(string refreshToken, string? userId = null, string? clientId = null)
    {
        var hashed = TokenHelper.HashToken(refreshToken);
        var query = _dbContext.RefreshTokens.Where(rt => rt.Token == hashed && !rt.IsRevoked);

        if (!string.IsNullOrWhiteSpace(userId))
        {
            query = query.Where(rt => rt.UserId == userId);
        }

        if (!string.IsNullOrWhiteSpace(clientId))
        {
            query = query.Where(rt => rt.ClientId == clientId);
        }

        var refreshTokenEntity = await query.FirstOrDefaultAsync();
        if (refreshTokenEntity == null)
        {
            throw new InvalidOperationException("Refresh token not found or does not belong to the specified user or client.");
        }

        refreshTokenEntity.IsRevoked = true;
        await _dbContext.SaveChangesAsync();
    }

    public async Task RevokeUserRefreshTokens(string userId)
    {
        var refreshTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked)
            .ToListAsync();

        foreach (var refreshToken in refreshTokens)
        {
            refreshToken.IsRevoked = true;
        }

        await _dbContext.SaveChangesAsync();
    }

    public async Task RevokeClientRefreshTokens(string clientId)
    {
        var refreshTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.ClientId == clientId && !rt.IsRevoked)
            .ToListAsync();

        foreach (var refreshToken in refreshTokens)
        {
            refreshToken.IsRevoked = true;
        }

        await _dbContext.SaveChangesAsync();
    }

    public async Task<bool> ValidateRefreshToken(string refreshToken, string? userId = null, string? clientId = null)
    {
        var hashed = TokenHelper.HashToken(refreshToken);
        var refreshTokenEntity = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == hashed && !rt.IsRevoked && rt.Expiry > DateTime.UtcNow);

        if (refreshTokenEntity == null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(userId) && refreshTokenEntity.UserId != userId)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(clientId) && refreshTokenEntity.ClientId != clientId)
        {
            return false;
        }

        return true;
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var secret = _config["Jwt:SecretKey"]
                ?? throw new InvalidOperationException("Jwt:SecretKey is missing.");
            var key = Encoding.UTF8.GetBytes(secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.Zero
            };

            return tokenHandler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }

    private static void AddRoleClaims(List<Claim> claims, IEnumerable<string>? roles)
    {
        if (roles == null)
        {
            return;
        }

        foreach (var role in roles)
        {
            if (!string.IsNullOrWhiteSpace(role))
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }
    }
}
