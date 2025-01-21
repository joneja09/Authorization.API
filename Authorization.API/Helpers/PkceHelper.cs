using System.Security.Cryptography;
using System.Text;

namespace Authorization.API.Helpers;

public static class PkceHelper
{
    public static string ComputeCodeChallenge(string codeVerifier, string? method)
    {
        if (method == "S256")
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Convert.ToBase64String(hash)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }
        return codeVerifier; // "plain" method (not recommended)
    }
}

