using Octopus.Data.Model;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    interface IAzureADConfigurationStore : IOpenIDConnectConfigurationWithRoleStore<AzureADConfiguration>
    {
        SensitiveString? GetClientSecret();
        void SetClientSecret(SensitiveString? clientSecret);
    }
}