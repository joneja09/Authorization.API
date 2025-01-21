namespace Authorization.API.Models;
public class ApiResource
{
    public int Id { get; set; }
    public string Name { get; set; }
    public ICollection<ApiScope> Scopes { get; set; }
}
