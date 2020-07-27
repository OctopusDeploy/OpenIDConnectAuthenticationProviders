using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    class GoogleAppsConfiguration : OpenIDConnectConfiguration
    {
        public GoogleAppsConfiguration() : base(GoogleAppsConfigurationStore.SingletonId, "GoogleApps", "Octopus Deploy", "1.0")
        {
            Issuer = "https://accounts.google.com";
        }

        public string? HostedDomain { get; set; }
    }
}