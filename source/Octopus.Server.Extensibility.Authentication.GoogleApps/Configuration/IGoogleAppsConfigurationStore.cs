using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    interface IGoogleAppsConfigurationStore : IOpenIDConnectConfigurationStore<GoogleAppsConfiguration>
    {
        string? GetHostedDomain();
        void SetHostedDomain(string? hostedDomain);
    }
}