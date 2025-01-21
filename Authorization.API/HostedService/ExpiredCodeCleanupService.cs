using Authorization.API.Context;

namespace Authorization.API.HostedService;
public class ExpiredCodeCleanupService : IHostedService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private Timer _timer;

    public ExpiredCodeCleanupService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _timer = new Timer(CleanupExpiredCodes, null, TimeSpan.Zero, TimeSpan.FromMinutes(30));
        return Task.CompletedTask;
    }

    private async void CleanupExpiredCodes(object state)
    {
        using var scope = _scopeFactory.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var expiredCodes = context.AuthorizationCodes
            .Where(c => c.ExpiresAt <= DateTime.UtcNow);

        if (expiredCodes.Any())
        {
            context.AuthorizationCodes.RemoveRange(expiredCodes);
            await context.SaveChangesAsync();
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }
}

