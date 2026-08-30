using Authorization.API.Context;
using Authorization.API.Models;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.Services;

public interface IClientService
{
    Task<Client?> GetClientById(string clientId);
    Task<IReadOnlyList<Client>> ListAsync(CancellationToken cancellationToken = default);
    Task<Client> CreateAsync(Client client, CancellationToken cancellationToken = default);
    Task UpdateAsync(Client client, CancellationToken cancellationToken = default);
    Task DeleteAsync(Client client, CancellationToken cancellationToken = default);
}

public class ClientService : IClientService
{
    private readonly ApplicationDbContext _dbContext;

    public ClientService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<Client?> GetClientById(string clientId)
    {
        return await _dbContext.Clients.FirstOrDefaultAsync(u => u.ClientId == clientId);
    }

    public async Task<IReadOnlyList<Client>> ListAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.Clients
            .OrderBy(c => c.ClientId)
            .ToListAsync(cancellationToken);
    }

    public async Task<Client> CreateAsync(Client client, CancellationToken cancellationToken = default)
    {
        _dbContext.Clients.Add(client);
        await _dbContext.SaveChangesAsync(cancellationToken);
        return client;
    }

    public async Task UpdateAsync(Client client, CancellationToken cancellationToken = default)
    {
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteAsync(Client client, CancellationToken cancellationToken = default)
    {
        _dbContext.Clients.Remove(client);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }
}
