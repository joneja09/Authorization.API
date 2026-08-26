namespace Authorization.API.Data;

public class SeedOptions
{
    public const string SectionName = "Seed";

    public bool Enabled { get; set; }

    public string AdminEmail { get; set; } = "admin@localhost";

    public string AdminPassword { get; set; } = "Admin123!";

    public string DemoUserEmail { get; set; } = "demo@example.com";

    public string DemoUserPassword { get; set; } = "Password1!";

    public string DemoClientId { get; set; } = "demo-client";

    public string DemoClientSecret { get; set; } = "demo-secret";

    public string DemoRedirectUri { get; set; } = "http://localhost:3000/callback";
}
