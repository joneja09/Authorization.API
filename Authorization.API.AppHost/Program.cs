var builder = DistributedApplication.CreateBuilder(args);

// Fixed local password so a persisted data volume keeps working across restarts.
// Override with the sql-password parameter / user secret if needed.
var sqlPassword = builder.AddParameter("sql-password", "LocalDev_Sql#2026", secret: true);

var database = builder.AddSqlServer("sql", password: sqlPassword)
    .WithDataVolume("authorization-sql-data")
    .AddDatabase("DefaultConnection");

builder.AddProject<Projects.Authorization_API>("authorization-api")
    .WithReference(database)
    .WaitFor(database)
    .WithExternalHttpEndpoints();

builder.Build().Run();
