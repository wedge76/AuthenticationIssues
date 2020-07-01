using System;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Serilog;
using myCompany.Base.EntityFrameworkCore.Migration;
using myCompany.Base.Security.Configuration;
using myCompany.Person.DataAccess.ClaimsManagement;

namespace myCompany.Person.Web
{
    public class Program
    {
        public static int Main(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                                .AddJsonFile("appsettings.json")
                                .AddEnvironmentVariables()
                                .Build();

            Log.Logger = new LoggerConfiguration()
                         .ReadFrom.Configuration(configuration)
                         .Enrich.WithThreadId()
                         .Enrich.WithThreadName()
                         .CreateLogger();
            try
            {
                Log.Information("Starting host...");
                var host = CreateHostBuilder(args).Build();

                MigrateDatabaseInDevelopment(host);

                host.Run();
                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly.");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilog()
                .UseServiceProviderFactory(new AutofacServiceProviderFactory())
                .ConfigureKeyVaultAppConfiguration<Startup>()
                .ConfigureWebHostDefaults(webBuilder =>
                                          {
                                              webBuilder.UseStartup<Startup>();
                                          });

        private static void MigrateDatabaseInDevelopment(IHost host)
        {
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            if (environment == Environments.Development)
            {
                host.MigrateDatabase<ClaimsDbContext>();
            }
        }
    }
}
