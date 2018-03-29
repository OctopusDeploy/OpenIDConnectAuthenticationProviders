﻿using System.Collections.Generic;
using Octopus.Node.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Node.Extensibility.HostServices.Mapping;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    public class AzureADConfigurationSettings : OpenIdConnectConfigurationSettings<AzureADConfiguration, AzureADConfigurationResource, IAzureADConfigurationStore>, IAzureADConfigurationSettings
    {
        public AzureADConfigurationSettings(IAzureADConfigurationStore configurationDocumentStore, IResourceMappingFactory factory) : base(configurationDocumentStore, factory)
        {
        }

        public override string Id => AzureADConfigurationStore.SingletonId;

        public override string Description => "Azure active directory authentication settings";

        public override IEnumerable<ConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }
            yield return new ConfigurationValue($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.RoleClaimType", ConfigurationDocumentStore.GetRoleClaimType(), ConfigurationDocumentStore.GetIsEnabled() && ConfigurationDocumentStore.GetRoleClaimType() != AzureADConfiguration.DefaultRoleClaimType, "Role Claim Type");
        }

    }
}