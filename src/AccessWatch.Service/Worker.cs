namespace AccessWatch.Service;

/// <summary>
/// Runs the AccessWatch background scan loop.
/// </summary>
public sealed class Worker : BackgroundService
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5);
    private readonly ServiceScanCoordinator coordinator;
    private readonly ILogger<Worker> logger;

    /// <summary>
    /// Initializes a new worker.
    /// </summary>
    /// <param name="coordinator">The scan coordinator.</param>
    /// <param name="logger">Logger for service diagnostics.</param>
    public Worker(ServiceScanCoordinator coordinator, ILogger<Worker> logger)
    {
        this.coordinator = coordinator;
        this.logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await coordinator.InitializeAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var createdEvents = await coordinator.RunListeningPortScanAsync(stoppingToken);
                logger.LogInformation("AccessWatch scan completed. Created {EventCount} new listening port events.", createdEvents);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "AccessWatch scan failed.");
            }

            await Task.Delay(ScanInterval, stoppingToken);
        }
    }
}
