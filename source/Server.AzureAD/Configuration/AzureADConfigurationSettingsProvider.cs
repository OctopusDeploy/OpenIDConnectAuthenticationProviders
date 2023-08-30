using System;
using System.Collections.Generic;
using Octopus.Data.Model;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigurationSettingsProvider : OpenIDConnectConfigurationSettingsProvider<AzureADConfiguration, AzureADConfigurationResource, IAzureADConfigurationStore>, IAzureADConfigurationSettings
    {
        public AzureADConfigurationSettingsProvider(IAzureADConfigurationStore configurationDocumentStore) : base(configurationDocumentStore)
        {
        }

        public override string Id => AzureADConfigurationStore.SingletonId;

        public override string ConfigurationSetName => "Azure AD";

        public override string Description => "Azure active directory authentication settings";

        public override IEnumerable<IConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }

            yield return new ConfigurationValue<string?>($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.RoleClaimType", ConfigurationDocumentStore.GetRoleClaimType(), ConfigurationDocumentStore.GetIsEnabled() && ConfigurationDocumentStore.GetRoleClaimType() != AzureADConfiguration.DefaultRoleClaimType, "Role Claim Type");
            yield return new ConfigurationValue<SensitiveString?>($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.ClientKey", ConfigurationDocumentStore.GetClientKey(), ConfigurationDocumentStore.GetIsEnabled(), "Client Access Key");
        }

        protected override AzureADConfigurationResource MapToResource(AzureADConfiguration model) => AzureADConfigurationMapper.MapToResource(model);
        protected override void ModifyModel(AzureADConfigurationResource resource, AzureADConfiguration model) => AzureADConfigurationMapper.ModifyModel(resource, model);
    }
}
