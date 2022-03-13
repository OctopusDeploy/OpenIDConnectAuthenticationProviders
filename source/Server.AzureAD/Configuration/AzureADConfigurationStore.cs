using Octopus.Data.Model;
using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigurationStore : OpenIdConnectConfigurationWithRoleStore<AzureADConfiguration>, IAzureADConfigurationStore
    {
        public const string SingletonId = "authentication-aad";

        public override string Id => SingletonId;

        public override string ConfigurationSettingsName => "AzureAD";

        public AzureADConfigurationStore(
            IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        public void SetClientSecret(SensitiveString? clientSecret)
        {
            SetProperty(doc => doc.ClientSecret = clientSecret);
        }

        public SensitiveString? GetClientSecret()
        {
            return GetProperty(doc => doc.ClientSecret);
        }
    }
}