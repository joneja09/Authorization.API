using Authorization.API.Helpers;

namespace Authorization.API.Tests;

public class PkceHelperTests
{
    [Fact]
    public void ComputeCodeChallenge_UsesS256()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = PkceHelper.ComputeCodeChallenge(verifier, PkceHelper.S256);

        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
        Assert.True(PkceHelper.Validate(verifier, challenge, PkceHelper.S256));
    }

    [Fact]
    public void ComputeCodeChallenge_RejectsPlainMethod()
    {
        Assert.Throws<ArgumentException>(() => PkceHelper.ComputeCodeChallenge("verifier", "plain"));
        Assert.False(PkceHelper.Validate("verifier", "verifier", "plain"));
    }

    [Fact]
    public void Validate_AllowsMissingChallengeWhenVerifierMissing()
    {
        Assert.True(PkceHelper.Validate(null, null, null));
        Assert.False(PkceHelper.Validate("verifier", null, PkceHelper.S256));
        Assert.False(PkceHelper.Validate(null, "challenge", PkceHelper.S256));
    }
}
