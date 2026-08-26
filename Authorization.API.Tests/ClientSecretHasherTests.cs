using Authorization.API.Services;

namespace Authorization.API.Tests;

public class ClientSecretHasherTests
{
    private readonly ClientSecretHasher _hasher = new();

    [Fact]
    public void HashAndVerify_RoundTrips()
    {
        var hash = _hasher.Hash("demo-secret");

        Assert.True(_hasher.IsHashed(hash));
        Assert.True(_hasher.Verify(hash, "demo-secret"));
        Assert.False(_hasher.Verify(hash, "other-secret"));
        Assert.NotEqual("demo-secret", hash);
    }

    [Fact]
    public void Verify_AcceptsLegacyPlaintextDuringUpgrade()
    {
        Assert.True(_hasher.Verify("demo-secret", "demo-secret"));
        Assert.False(_hasher.Verify("demo-secret", "nope"));
    }
}
