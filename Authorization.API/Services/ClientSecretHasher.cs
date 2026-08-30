using Microsoft.AspNetCore.Identity;

namespace Authorization.API.Services;

public interface IClientSecretHasher
{
    string Hash(string secret);
    bool Verify(string hashedSecret, string? providedSecret);
    bool IsHashed(string value);
}

public class ClientSecretHasher : IClientSecretHasher
{
    private static readonly object Sentinel = new();
    private readonly PasswordHasher<object> _hasher = new();

    public string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        return _hasher.HashPassword(Sentinel, secret);
    }

    public bool Verify(string hashedSecret, string? providedSecret)
    {
        if (string.IsNullOrEmpty(hashedSecret) || string.IsNullOrEmpty(providedSecret))
        {
            return false;
        }

        if (!IsHashed(hashedSecret))
        {
            return TokenHelperEquals(hashedSecret, providedSecret);
        }

        var result = _hasher.VerifyHashedPassword(Sentinel, hashedSecret, providedSecret);
        return result != PasswordVerificationResult.Failed;
    }

    public bool IsHashed(string value)
    {
        return !string.IsNullOrEmpty(value)
            && value.StartsWith("AQAAAA", StringComparison.Ordinal);
    }

    private static bool TokenHelperEquals(string stored, string provided)
    {
        return Helpers.TokenHelper.SecretsEqual(stored, provided);
    }
}
