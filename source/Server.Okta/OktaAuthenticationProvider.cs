﻿using System;
using System.Collections.Generic;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;

namespace Octopus.Server.Extensibility.Authentication.Okta
{
    public class OktaAuthenticationProvider : OpenIDConnectAuthenticationProvider<IOktaConfigurationStore>
    {
        public const string ProviderName = "Okta";

        public OktaAuthenticationProvider(ILog log, IOktaConfigurationStore configurationStore) : base(log, configurationStore)
        {
        }

        public override string IdentityProviderName => ProviderName;
        public override string FilenamePrefix => "okta";

        protected override IEnumerable<string> ReasonsWhyConfigIsIncomplete()
        {
            var issuer = ConfigurationStore.GetIssuer();
            if (string.IsNullOrWhiteSpace(issuer))
                yield return $"No {IdentityProviderName} issuer specified";
            if (!Uri.IsWellFormedUriString(issuer, UriKind.Absolute))
                yield return $"The {IdentityProviderName} issuer must be an absolute URI (expected format: https://dev-[customer id]-admin.oktapreview.com)";
            if (string.IsNullOrWhiteSpace(ConfigurationStore.GetClientId()))
                yield return $"No {IdentityProviderName} Client ID specified";
        }
    }
}
