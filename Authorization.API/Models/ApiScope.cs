namespace Authorization.API.Models;

public class ApiScope
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}
