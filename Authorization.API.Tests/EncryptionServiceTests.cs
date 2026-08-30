using Authorization.API.Services;

namespace Authorization.API.Tests;

public class EncryptionServiceTests
{
    private const string DevKey = "TG9jYWxEZXYtQUVTMjU2LUVuY3J5cHRpb24tS2V5cyE=";

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var service = new EncryptionService(DevKey);
        const string original = "authorization-code";

        var encrypted = service.Encrypt(original);
        var decrypted = service.Decrypt(encrypted);

        Assert.NotEqual(original, encrypted);
        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void Encrypt_UsesUniqueCipherText()
    {
        var service = new EncryptionService(DevKey);

        var first = service.Encrypt("same-value");
        var second = service.Encrypt("same-value");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Constructor_RejectsInvalidKeyLength()
    {
        var shortKey = Convert.ToBase64String("tooshort"u8.ToArray());
        Assert.Throws<ArgumentException>(() => new EncryptionService(shortKey));
    }
}
