﻿using System.Collections.Generic;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    public class OktaConfigurationSettings : OpenIdConnectConfigurationSettings<OktaConfiguration, OktaConfigurationResource, IOktaConfigurationStore>, IOktaConfigurationSettings
    {
        public OktaConfigurationSettings(IOktaConfigurationStore configurationDocumentStore) : base(configurationDocumentStore)
        {
        }

        public override string Id => OktaConfigurationStore.SingletonId;
        public override string Description => "Okta authentication settings";

        public override IEnumerable<ConfigurationValue> GetConfigurationValues()
        {
            foreach (var configurationValue in base.GetConfigurationValues())
            {
                yield return configurationValue;
            }
            yield return new ConfigurationValue($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.RoleClaimType", ConfigurationDocumentStore.GetRoleClaimType(), ConfigurationDocumentStore.GetIsEnabled() && ConfigurationDocumentStore.GetRoleClaimType() != OktaConfiguration.DefaultRoleClaimType, "Role Claim Type");
            yield return new ConfigurationValue($"Octopus.{ConfigurationDocumentStore.ConfigurationSettingsName}.UsernameClaimType", ConfigurationDocumentStore.GetUsernameClaimType(), ConfigurationDocumentStore.GetIsEnabled() && ConfigurationDocumentStore.GetUsernameClaimType() != OktaConfiguration.DefaultUsernameClaimType, "Username Claim Type");
        }
    }
}