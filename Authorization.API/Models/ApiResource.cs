namespace Authorization.API.Models;

public class ApiResource
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public ICollection<ApiScope> Scopes { get; set; } = new List<ApiScope>();
}
