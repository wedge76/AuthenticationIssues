using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Autofac;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Serilog;
using myCompany.Base.Common;
using myCompany.Base.Configuration;
using myCompany.Base.Conversion;
using myCompany.Base.Core.Configuration;
using myCompany.Base.Core.Configuration.Localization;
using myCompany.Base.Dal.SqlServer.ConnectionThrottling;
using myCompany.Base.IO.Modules;
using myCompany.Base.Modules;
using myCompany.Base.Net;
using myCompany.Base.Security;
using myCompany.Base.Net.Mail;
using myCompany.Base.Security.Cryptography;
using myCompany.Base.Security.NWebSec;
using myCompany.Base.Security.NWebSec.Web;
using myCompany.Person.Application.Modules;
using myCompany.Person.DataAccess.ClaimsManagement;
using myCompany.Person.DataAccess.ClaimsManagement.Configuration;
using myCompany.Person.DataAccess.Migration.SqlServer;
using myCompany.Person.DataAccess.Modules;
using myCompany.Person.DataAccess.PersonInteraction;
using myCompany.Person.Domain;
using myCompany.Person.Domain.PersonInteraction.Dto;
using myCompany.Person.Identity;
using myCompany.Person.Identity.Stores;
using myCompany.Person.Web.Authentication.Login;
using myCompany.Person.Web.Authorization;
using myCompany.Person.Web.Configuration;
using myCompany.Person.Web.Redirecting;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.WebSso;
using IConfiguration = Microsoft.Extensions.Configuration.IConfiguration;
using IdentityProvider = Sustainsys.Saml2.IdentityProvider;

namespace myCompany.Person.Web
{
    public class Startup
    {
        private const int SqlConnectionMaxRetryCount = 10;

        private string _sharedAuthTicketKeys = @"c:\folderForSharedKeys\";

        private readonly IWebHostEnvironment _environment;

        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            _environment = env;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            Log.Information($"Start configuring services. Environment: {_environment.EnvironmentName}");
            services.AddControllersWithViews();

            services.AddIdentity<LoginInputModel, RoleDto>()
                    .AddDefaultTokenProviders();

            var certificate = LoadSigningCertificate();
            var identityServerBuilder = services.AddIdentityServer(options =>
                                                                   {
                                                                       options.Events.RaiseErrorEvents = true;
                                                                       options.Events.RaiseInformationEvents = true;
                                                                       options.Events.RaiseFailureEvents = true;
                                                                       options.Events.RaiseSuccessEvents = true;
                                                                   })
                                                .AddSigningCredential(certificate)
                                                .AddProfileService<ProfileService>()
                                                .AddInMemoryIdentityResources(Config.Ids)
                                                .AddInMemoryApiResources(Config.Apis)
                                                .AddInMemoryClients(new ClientConfigLoader().LoadClients(Configuration));

            if (_environment.IsDevelopment())
            {
                identityServerBuilder.AddDeveloperSigningCredential();
            }

            services.Configure<CookiePolicyOptions>(options =>
                                                    {
                                                        options.CheckConsentNeeded = context => false;
                                                        options.MinimumSameSitePolicy = SameSiteMode.None;
                                                    });

            services.AddDataProtection()
                    .PersistKeysToFileSystem(new DirectoryInfo(_sharedAuthTicketKeys))
                    .SetApplicationName("SharedCookieApp");

            services.AddAsposeMailLicense(Configuration);
            var optionalStartupSettings = SetupStartupSettings();
            if (optionalStartupSettings.IsSome)
            {
                var settings = optionalStartupSettings.Value;

                services.ConfigureApplicationCookie(options =>
                                                    {
                                                        options.AccessDeniedPath = new PathString("/Account/AccessDenied");
                                                        options.Cookie.Name = ".AspNetCore.Auth.Cookie";
                                                        options.Cookie.Path = "/";
                                                        options.Cookie.HttpOnly = true;
                                                        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                                                        options.LoginPath = new PathString("/account/login");
                                                        options.Cookie.SameSite = SameSiteMode.None;
                                                    });

				var authBuilder = services.AddAuthentication(options => { options.DefaultAuthenticateScheme = "Identity.Application"; });
				authBuilder = ConfigureSaml2(authBuilder, settings);
				authBuilder = ConfigureGoogle(authBuilder);
				authBuilder.AddCookie();
            }
            else
            {
                throw new InvalidOperationException($"Startup settings are not configured in appsettings.json.");
            }

            SetupEntityFramework(services);
        }

        private X509Certificate2 LoadSigningCertificate()
        {
            var useLocalCertStore = Convert.ToBoolean(Configuration["UseLocalCertStore"]);
            var certificateThumbprint = Configuration["KeyVault:AzureADCertThumbprint"];

            X509Certificate2 cert;

            if (_environment.IsStaging() || _environment.IsProduction())
            {
                if (useLocalCertStore)
                {
                    Log.Information("Loading signing certificate from local certification store");
                    using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                    {
                        store.Open(OpenFlags.ReadOnly);
                        var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);
                        cert = certs[0];
                        store.Close();
                    }
                }
                else
                {
                    Log.Information("Loading signing certificate from key vault");
                    var vaultConfigSection = Configuration.GetSection("KeyVault");
                    Log.Information($"Key vault configurations. KeyVaultName: {vaultConfigSection["KeyVaultName"]}; "
                                    + $"CertificateName: {vaultConfigSection["CertificateName"]}");
                    var keyVaultService = new KeyVaultCertificateService($"https://{vaultConfigSection["KeyVaultName"]}.vault.azure.net/",
                                                                         vaultConfigSection["AzureADApplicationId"],
                                                                         vaultConfigSection["ClientSecret"]);
                    cert = keyVaultService.GetCertificateFromKeyVault(vaultConfigSection["CertificateName"]);
                }
            }
            else
            {
                Log.Information("Loading signing certificate from file");
                cert = new X509Certificate2(Path.Combine(_environment.ContentRootPath, "keyvault-myCompany-ch-20191219.pfx"), "");
            }

            return cert;
        }

        private void SetupAuthentication(IServiceCollection services, StartupSettings settings)
        {
            var authBuilder = services.AddAuthentication(options => { options.DefaultAuthenticateScheme = "Identity.Application"; });
            authBuilder = ConfigureSaml2(authBuilder, settings);
            authBuilder.AddCookie();
        }

        private AuthenticationBuilder ConfigureSaml2(AuthenticationBuilder authBuilder, StartupSettings settings)
        {
            foreach (var provider in settings.Saml2.IdentityProviders)
            {
                authBuilder = authBuilder.AddSaml2(provider.Name,
                                                   options =>
                                                   {
                                                       options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                                                       options.SPOptions.EntityId = new EntityId(settings.Saml2.EntityId);

                                                       var preferredIdp = settings.Saml2.IdentityProviders.Single(idp => idp.Name == provider.Name);
                                                       ConfigureSamlIdp(preferredIdp, options);

                                                       foreach (var identityProvider in settings.Saml2.IdentityProviders.Except(new[]
                                                                                                                                {
                                                                                                                                    preferredIdp
                                                                                                                                }))
                                                       {
                                                           ConfigureSamlIdp(identityProvider, options);
                                                       }
                                                   });
            }

            return authBuilder;
        }

        private static void ConfigureSamlIdp(Configuration.IdentityProvider identityProvider, Saml2Options options)
        {
            Log.Information($"Adding EntityId: {identityProvider.EntityId}");
            var idp = new IdentityProvider(new EntityId(identityProvider.EntityId), options.SPOptions)
                      {
                          Binding = Saml2BindingType.HttpRedirect,
                          SingleSignOnServiceUrl = new Uri(identityProvider.SignOnUrl),
                      };
            if (identityProvider.LoadMetadata)
            {
                idp.MetadataLocation = identityProvider.MetadataLocation;
                idp.LoadMetadata = true;
            }
            else
            {
                Log.Information($"Adding certificate. Name: {identityProvider.CertificateName}");
                idp.SigningKeys.AddConfiguredKey(new X509Certificate2(identityProvider.CertificateName));
            }

            options.IdentityProviders.Add(idp);
        }

        private void SetupEntityFramework(IServiceCollection services)
        {
            var assemblyName = typeof(PersonDbContextFactory).Assembly.GetName();
            services.AddDbContext<ClaimsDbContext>(options =>
                                                   {
                                                       var settings = Configuration.CreateConfiguredSettingsInstance<RepositorySettings>();
                                                       options.UseSqlServer(settings.myCompanyConnectionString,
                                                                            sqlOptions =>
                                                                            {
                                                                                sqlOptions.MigrationsAssembly(assemblyName.Name);
                                                                                sqlOptions.MigrationsHistoryTable(HistoryRepository.DefaultTableName,
                                                                                                                  ConfigurationConstants.SchemaName);
                                                                                sqlOptions.EnableRetryOnFailure(maxRetryCount: SqlConnectionMaxRetryCount,
                                                                                                                maxRetryDelay: TimeSpan.FromSeconds(30),
                                                                                                                errorNumbersToAdd: null);
                                                                            });
                                                   });
        }

        public void ConfigureContainer(ContainerBuilder builder)
        {
            RegisterModules(builder);

            RegisterConfigs(builder);
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseCors(builder =>
                            {
                                builder.WithOrigins("http://localhost",
                                                    "https://localhost",
                                                    "http://localhost:3000",
                                                    "https://localhost:3000")
                                       .AllowAnyHeader()
                                       .AllowAnyMethod()
                                       .AllowCredentials();
                            });
                IdentityModelEventSource.ShowPII = true;
            }
            else if (env.IsStaging())
            {
                app.UseCors(builder =>
                            {
                                builder.WithOrigins("https://localhost:3000")
                                       .AllowAnyHeader()
                                       .AllowAnyMethod()
                                       .AllowCredentials();
                            });
            }
            else
            {
                app.UseExceptionHandler(HandleExceptionAndRedirectToErrorPage());
                //NWebSec: Registered before static files to always set header
                app.NwebSecWebPreStaticFilesSetup();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles()
               .UseCookiePolicy()
               .UseRouting();
			   
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseRequestLocalization();

            if (!env.IsDevelopment())
            {
                //NWebSec: Registered after static files, to set headers for dynamic content.
                app.NwebSecWebPostStaticFilesSetup();
            }

            app.UseEndpoints(endpoints =>
                             {
                                 endpoints.MapControllerRoute(name: "default_with_langCode",
                                                              pattern: "{languageCode}/{controller=Home}/{action=Index}");
                                 endpoints.MapDefaultControllerRoute();
                             });
        }

        private Action<IApplicationBuilder> HandleExceptionAndRedirectToErrorPage()
        {
            return configure =>
                   {
                       configure.Run(async context =>
                                     {
                                         var exception = context.Features.Get<IExceptionHandlerFeature>().Error;
                                         var logger = context.RequestServices.GetService<ILogger<Startup>>();
                                         logger.LogError(exception, "Uncaught exception");

                                         var rqf = context.Features.Get<IRequestCultureFeature>();
                                         var culture = rqf.RequestCulture.Culture;

                                         var defaultReturnUrl = $"{context.Request.Scheme}://{context.Request.Host.Value}{context.Request.PathBase.Value.Replace("/person", String.Empty)}/{culture.TwoLetterISOLanguageName}/error";

                                         context.Response.Redirect(defaultReturnUrl);
                                         await Task.CompletedTask;
                                     });
                   };
        }

        private void RegisterModules(ContainerBuilder builder)
        {
            builder.RegisterModule<WebModule>();
            builder.RegisterModule<DataAccessModule>();
            builder.RegisterModule<ApplicationModule>();
            builder.RegisterModule<DomainModule>();
            builder.RegisterModule<IdentityModule>();
            builder.RegisterModule<ConversionModule>();
            builder.RegisterModule<BaseModule>();
            builder.RegisterModule<NetModule>();
            builder.RegisterModule<SecurityModule>();
            builder.RegisterModule<IoModule>();
            builder.RegisterModule<Base.Dal.SqlServer.Modules.SqlServerModule>();
        }

        private void RegisterConfigs(ContainerBuilder builder)
        {
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(RepositorySettings).Assembly);
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(Settings).Assembly);
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(MailServiceConfig).Assembly);
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(ThrottlingConfig).Assembly);
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(NWebSecConfig).Assembly);
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(UserRedirectionConfig).Assembly);
            builder.RegisterAllConfigurationsInAssembly(Configuration, typeof(StartupSettings).Assembly);
        }

        private Option<StartupSettings> SetupStartupSettings()
        {
            var section = typeof(StartupSettings).GetCustomAttribute<ConfigSectionAttribute>();
            if (section != null)
            {
                var settings = new StartupSettings();
                Configuration.GetSection(section.SectionName).Bind(settings);

                return Option<StartupSettings>.Some(settings);
            }

            return Option<StartupSettings>.None();
        }
    }
}