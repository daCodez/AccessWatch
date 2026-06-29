using AccessWatch.Core;
using AccessWatch.Data;
using AccessWatch.Detection;
using AccessWatch.Notifications;
using AccessWatch.Rules;
using AccessWatch.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services
    .AddWindowsService(options => options.ServiceName = "AccessWatch")
    .AddAccessWatchCore()
    .AddAccessWatchData(builder.Configuration)
    .AddAccessWatchDetection()
    .AddAccessWatchRules()
    .AddAccessWatchNotifications()
    .AddSingleton<ServiceScanCoordinator>()
    .AddHostedService<Worker>();

var host = builder.Build();
host.Run();

