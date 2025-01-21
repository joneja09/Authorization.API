
using Microsoft.AspNetCore.Identity;

namespace Authorization.API.Models;
public class ApplicationUser : IdentityUser
{
    public string? FullName { get; set; }

    public ICollection<IdentityUserClaim<string>> Claims { get; set; }

}
