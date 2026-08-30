using System.Security.Cryptography;
using System.Text;

namespace Authorization.API.Helpers;

public static class TokenHelper
{
    public static string GenerateSecureCode(int length = 32)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return ToUrlSafeBase64(bytes);
    }

    public static string HashToken(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hash);
    }

    public static string ToUrlSafeBase64(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace("+", "-", StringComparison.Ordinal)
            .Replace("/", "_", StringComparison.Ordinal)
            .TrimEnd('=');
    }

    public static bool SecretsEqual(string? stored, string? provided)
    {
        var left = Encoding.UTF8.GetBytes(stored ?? string.Empty);
        var right = Encoding.UTF8.GetBytes(provided ?? string.Empty);

        if (left.Length != right.Length)
        {
            CryptographicOperations.FixedTimeEquals(left, left);
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(left, right);
    }
}
