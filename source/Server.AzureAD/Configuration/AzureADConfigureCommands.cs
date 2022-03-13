﻿using System;
using System.Collections.Generic;
using Octopus.Data.Model;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigureCommands : OpenIdConnectConfigureCommands<IAzureADConfigurationStore>
    {
        public AzureADConfigureCommands(
            ISystemLog log,
            Lazy<IAzureADConfigurationStore> configurationStore,
            Lazy<IWebPortalConfigurationStore> webPortalConfigurationStore)
            : base(log, configurationStore, webPortalConfigurationStore)
        {
        }

        protected override string ConfigurationSettingsName => "azureAD";

        public override IEnumerable<ConfigureCommandOption> GetOptions()
        {
            foreach (var option in base.GetOptions())
            {
                yield return option;
            }
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}RoleClaimType=", "Tell Octopus how to find the roles in the security token from Azure Active Directory.", v =>
            {
                ConfigurationStore.Value.SetRoleClaimType(v);
                Log.Info($"{ConfigurationSettingsName} RoleClaimType set to: {v}");
            });
            yield return new ConfigureCommandOption($"{ConfigurationSettingsName}ClientSecret=", "A client secret from the Octopus App Registration in AzureAD. Used for authenticating to the Microsoft Graph API when necessary", v =>
            {
                if (!string.IsNullOrEmpty(v))
                {
                    ConfigurationStore.Value.SetClientSecret(v.ToSensitiveString());
                    Log.Info($"{ConfigurationSettingsName} ClientSecret was set.");
                }
            });
        }
    }
}