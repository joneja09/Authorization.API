var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.Authorization_API>("authorization-api");

builder.Build().Run();
