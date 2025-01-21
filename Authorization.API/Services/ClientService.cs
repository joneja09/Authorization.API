using Authorization.API.Context;
using Authorization.API.Models;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.Services;

/// <summary>
/// The client service interface.
/// </summary>
public interface IClientService
{
    /// <summary>
    /// Get client by id.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <returns><![CDATA[Task<Client?>]]></returns>
    Task<Client?> GetClientById(string clientId);
}

/// <summary>
/// The client service.
/// </summary>
public class ClientService : IClientService
{
    /// <summary>
    /// The db context.
    /// </summary>
    private readonly ApplicationDbContext _dbContext;
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientService"/> class.
    /// </summary>
    /// <param name="dbContext">The db context.</param>
    public ClientService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    /// <summary>
    /// Get client by id.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <returns><![CDATA[Task<Client?>]]></returns>
    public async Task<Client?> GetClientById(string clientId)
    {
        return await _dbContext.Clients.FirstOrDefaultAsync(u => u.ClientId == clientId);
    }

}
