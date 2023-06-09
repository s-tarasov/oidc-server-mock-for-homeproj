using System.Reactive.Linq;
using System.Security.Claims;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using OpenIdConnectServer.Helpers;
using OpenIdConnectServer.YamlConverters;
using YamlDotNet.Serialization;

namespace OpenIdConnectServer
{
    public static class Config
    {
        private static FileSystemWatcher _watcher;

        public static AspNetServicesOptions GetAspNetServicesOptions()
        {
            string aspNetServicesOptionsStr = Environment.GetEnvironmentVariable("ASPNET_SERVICES_OPTIONS_INLINE");
            if (string.IsNullOrWhiteSpace(aspNetServicesOptionsStr))
            {
                var aspNetServicesOptionsPath = Environment.GetEnvironmentVariable("ASPNET_SERVICES_OPTIONS_PATH");
                if (string.IsNullOrWhiteSpace(aspNetServicesOptionsPath))
                {
                    return new AspNetServicesOptions();
                }
                aspNetServicesOptionsStr = File.ReadAllText(aspNetServicesOptionsPath);
            }
            var aspNetServicesOptions = DeserializeObject<AspNetServicesOptions>(aspNetServicesOptionsStr);
            return aspNetServicesOptions;
        }

        public static IdentityServerOptions GetServerOptions()
        {
            string serverOptionsStr = Environment.GetEnvironmentVariable("SERVER_OPTIONS_INLINE");
            if (string.IsNullOrWhiteSpace(serverOptionsStr))
            {
                var serverOptionsFilePath = Environment.GetEnvironmentVariable("SERVER_OPTIONS_PATH");
                if (string.IsNullOrWhiteSpace(serverOptionsFilePath))
                {
                    return new IdentityServerOptions();
                }
                serverOptionsStr = File.ReadAllText(serverOptionsFilePath);
            }
            var serverOptions = DeserializeObject<IdentityServerOptions>(serverOptionsStr);
            return serverOptions;
        }

        public static void ConfigureOptions<T>(string optionsName)
        {
            string optionsStr = Environment.GetEnvironmentVariable($"{optionsName.ToUpper()}_OPTIONS_INLINE");
            if (string.IsNullOrWhiteSpace(optionsStr))
            {
                var optionsFilePath = Environment.GetEnvironmentVariable($"{optionsName.ToUpper()}_OPTIONS_PATH");
                if (string.IsNullOrWhiteSpace(optionsFilePath))
                {
                    return;
                }
                optionsStr = File.ReadAllText(optionsFilePath);
            }
            OptionsHelper.ConfigureOptions<T>(optionsStr);
        }

        public static IEnumerable<string> GetServerCorsAllowedOrigins()
        {
            string allowedOriginsStr = Environment.GetEnvironmentVariable("SERVER_CORS_ALLOWED_ORIGINS_INLINE");
            if (string.IsNullOrWhiteSpace(allowedOriginsStr))
            {
                var allowedOriginsFilePath = Environment.GetEnvironmentVariable("SERVER_CORS_ALLOWED_ORIGINS_PATH");
                if (string.IsNullOrWhiteSpace(allowedOriginsFilePath))
                {
                    return null;
                }
                allowedOriginsStr = File.ReadAllText(allowedOriginsFilePath);
            }
            var allowedOrigins = DeserializeObject<IEnumerable<string>>(allowedOriginsStr);
            return allowedOrigins;
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            string apiScopesStr = Environment.GetEnvironmentVariable("API_SCOPES_INLINE");
            if (string.IsNullOrWhiteSpace(apiScopesStr))
            {
                var apiScopesFilePath = Environment.GetEnvironmentVariable("API_SCOPES_PATH");
                if (string.IsNullOrWhiteSpace(apiScopesFilePath))
                {
                    return new List<ApiScope>();
                }
                apiScopesStr = File.ReadAllText(apiScopesFilePath);
            }
            var apiScopes = DeserializeObject<IEnumerable<ApiScope>>(apiScopesStr);
            return apiScopes;
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            string apiResourcesStr = Environment.GetEnvironmentVariable("API_RESOURCES_INLINE");
            if (string.IsNullOrWhiteSpace(apiResourcesStr))
            {
                var apiResourcesFilePath = Environment.GetEnvironmentVariable("API_RESOURCES_PATH");
                if (string.IsNullOrWhiteSpace(apiResourcesFilePath))
                {
                    return new List<ApiResource>();
                }
                apiResourcesStr = File.ReadAllText(apiResourcesFilePath);
            }
            var apiResources = DeserializeObject<IEnumerable<ApiResource>>(apiResourcesStr);
            return apiResources;
        }

        public static IEnumerable<Client> GetClients()
        {
            string configStr = Environment.GetEnvironmentVariable("CLIENTS_CONFIGURATION_INLINE");
            if (string.IsNullOrWhiteSpace(configStr))
            {
                var configFilePath = Environment.GetEnvironmentVariable("CLIENTS_CONFIGURATION_PATH") ?? "clients-config.json";
                if (string.IsNullOrWhiteSpace(configFilePath))
                {
                    throw new ArgumentNullException("You must set either CLIENTS_CONFIGURATION_INLINE or CLIENTS_CONFIGURATION_PATH env variable");
                }
                configStr = File.ReadAllText(configFilePath);
            }
            var configClients = DeserializeObject<IEnumerable<Client>>(configStr);
            return configClients;
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return GetCustomIdentityResources().ToArray();

            IEnumerable <IdentityResource> identityResources = new List<IdentityResource>();
            var overrideStandardResources = Environment.GetEnvironmentVariable("OVERRIDE_STANDARD_IDENTITY_RESOURCES");
            if (string.IsNullOrEmpty(overrideStandardResources) || Boolean.Parse(overrideStandardResources) != true)
            {
                var standardResources = new List<IdentityResource>
                {
                    new IdentityResources.OpenId(),
                    new IdentityResources.Profile(),
                    new IdentityResources.Email()
                };
                identityResources = identityResources.Union(standardResources);
            }
            return identityResources.Union(GetCustomIdentityResources());
        }

        public static List<TestUser> GetUsers()
        {
            List<TestUser> testUsers = new List<TestUser>();
            string configStr = Environment.GetEnvironmentVariable("USERS_CONFIGURATION_INLINE");
            if (string.IsNullOrWhiteSpace(configStr))
            {
                var configFilePath = Environment.GetEnvironmentVariable("USERS_CONFIGURATION_PATH") ?? "users-config.yaml";
                if (string.IsNullOrWhiteSpace(configFilePath))
                {
                    return new List<TestUser>();
                }
                configStr = File.ReadAllText(configFilePath);
                WhenFileChanged(configFilePath)
                    .Subscribe(e =>
                    {
                        Console.WriteLine("Reload users config.");
                        try
                        {
                            configStr = File.ReadAllText(configFilePath);
                            testUsers.Clear();
                            AddUsers(configStr);
                        }
                        catch (Exception exception)
                        {
                            Console.WriteLine(exception);
                        }
                    });
            }

            AddUsers(configStr);

            return testUsers;

            void AddUsers(string configContent)
            {
                var configUsers = DeserializeObject<List<CustomTestUser>>(configContent);
                foreach (var user in configUsers)
                    foreach (var stringClaim in user.StringClaims)
                        user.Claims.Add(new Claim(stringClaim.Key, stringClaim.Value));
                
                testUsers.AddRange(configUsers.Cast<TestUser>());
            }
        }

        private static IObservable<FileSystemEventArgs> WhenFileChanged(string configFilePath)
        {
            _watcher = new FileSystemWatcher(Path.GetDirectoryName(Path.GetFullPath(configFilePath))!);
            _watcher.Filter = Path.GetFileName(configFilePath);
            _watcher.NotifyFilter = NotifyFilters.LastWrite; 
            
            _watcher.Error += (_, e) => Console.WriteLine(e.GetException());

            var whenFileChanged = Observable.FromEvent<FileSystemEventHandler, FileSystemEventArgs>(handler =>
            {
                return (sender, e) => handler(e);
            },
            fsHandler => _watcher.Changed += fsHandler,
            fsHandler => _watcher.Changed -= fsHandler);

            _watcher.EnableRaisingEvents = true;

            return whenFileChanged
                .Throttle(TimeSpan.FromSeconds(1));
        }

        private static IEnumerable<IdentityResource> GetCustomIdentityResources()
        {
            string identityResourcesStr = Environment.GetEnvironmentVariable("IDENTITY_RESOURCES_INLINE");
            if (string.IsNullOrWhiteSpace(identityResourcesStr))
            {
                var identityResourcesFilePath = Environment.GetEnvironmentVariable("IDENTITY_RESOURCES_PATH") ?? "identity-resources-config.yaml";
                if (string.IsNullOrWhiteSpace(identityResourcesFilePath))
                {
                    return new List<IdentityResource>();
                }
                identityResourcesStr = File.ReadAllText(identityResourcesFilePath);
            }

            var identityResourceConfig = DeserializeObject<IdentityResourceConfig[]>(identityResourcesStr);
            return identityResourceConfig.Select(c => new IdentityResource(c.Name, c.ClaimTypes));
        }

        private static T DeserializeObject<T>(string value)
        {
            var deserializer = new DeserializerBuilder()
                .WithTypeConverter(new ClaimYamlConverter())
                .WithTypeConverter(new SecretYamlConverter())
                .Build();
            return deserializer.Deserialize<T>(value);
        }

        private class IdentityResourceConfig
        {
            public string Name { get; set; }
            public IEnumerable<string> ClaimTypes { get; set; }
        }
    }
}

public class CustomTestUser : TestUser
{
    public Dictionary<string, string> StringClaims { get; set; }
}
