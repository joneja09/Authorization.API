using Authorization.API.Context;
using Microsoft.EntityFrameworkCore;

namespace Authorization.API.HostedService;

public class ExpiredCodeCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ExpiredCodeCleanupService> _logger;

    public ExpiredCodeCleanupService(IServiceScopeFactory scopeFactory, ILogger<ExpiredCodeCleanupService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(30));

            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await CleanupAsync(stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Failed to clean expired authorization data.");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host is shutting down.
        }
    }

    private async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var expiredCodes = await context.AuthorizationCodes
            .Where(c => c.ExpiresAt <= DateTime.UtcNow || c.IsUsed)
            .ExecuteDeleteAsync(cancellationToken);

        var expiredTokens = await context.RefreshTokens
            .Where(t => t.Expiry <= DateTime.UtcNow)
            .ExecuteDeleteAsync(cancellationToken);

        if (expiredCodes > 0 || expiredTokens > 0)
        {
            _logger.LogInformation(
                "Removed {ExpiredCodes} authorization codes and {ExpiredTokens} refresh tokens.",
                expiredCodes,
                expiredTokens);
        }
    }
}
