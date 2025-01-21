namespace Authorization.API.Models;

public class ApiScope
{
    public int Id { get; set; }
    public string Name { get; set; } // e.g., "read", "write", "profile"
    public string Description { get; set; }
}
