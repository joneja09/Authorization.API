using System.Security.Cryptography;
using System.Text;

namespace Authorization.API.Helpers;

public static class PkceHelper
{
    public const string S256 = "S256";

    public static string ComputeCodeChallenge(string codeVerifier, string? method)
    {
        if (!string.Equals(method, S256, StringComparison.Ordinal))
        {
            throw new ArgumentException("Only the S256 PKCE method is supported.", nameof(method));
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        return TokenHelper.ToUrlSafeBase64(hash);
    }

    public static bool Validate(string? verifier, string? challenge, string? method)
    {
        if (string.IsNullOrEmpty(challenge))
        {
            return string.IsNullOrEmpty(verifier);
        }

        if (string.IsNullOrEmpty(verifier) || !string.Equals(method, S256, StringComparison.Ordinal))
        {
            return false;
        }

        var expected = ComputeCodeChallenge(verifier, method);
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(challenge);

        return expectedBytes.Length == actualBytes.Length
            && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}
