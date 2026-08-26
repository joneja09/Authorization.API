using Authorization.API.Helpers;

namespace Authorization.API.Tests;

public class TokenHelperTests
{
    [Fact]
    public void HashToken_IsDeterministicAndNotReversible()
    {
        var token = "refresh-token-value";

        var first = TokenHelper.HashToken(token);
        var second = TokenHelper.HashToken(token);

        Assert.Equal(first, second);
        Assert.NotEqual(token, first);
        Assert.Equal(64, first.Length);
    }

    [Fact]
    public void GenerateSecureCode_IsUrlSafe()
    {
        var code = TokenHelper.GenerateSecureCode();

        Assert.False(string.IsNullOrWhiteSpace(code));
        Assert.DoesNotContain("+", code);
        Assert.DoesNotContain("/", code);
        Assert.DoesNotContain("=", code);
    }

    [Fact]
    public void SecretsEqual_ComparesExactValues()
    {
        Assert.True(TokenHelper.SecretsEqual("secret", "secret"));
        Assert.False(TokenHelper.SecretsEqual("secret", "Secret"));
        Assert.False(TokenHelper.SecretsEqual("secret", "other"));
        Assert.False(TokenHelper.SecretsEqual(null, "secret"));
    }
}
