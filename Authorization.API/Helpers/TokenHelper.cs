using System.Security.Cryptography;

namespace Authorization.API.Helpers;

public static class TokenHelper
{
    public static string GenerateSecureCode(int length = 32)
    {
        var bytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-") // URL-safe
            .Replace("/", "_")
            .TrimEnd('=');
    }
}

