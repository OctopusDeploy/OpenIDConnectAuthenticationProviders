﻿using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Tokens
{
    class AzureADAuthTokenHandler : OpenIDConnectAuthTokenWithRolesHandler<IAzureADConfigurationStore, IAzureADKeyRetriever, IIdentityProviderConfigDiscoverer>, IAzureADAuthTokenHandler
    {
        public AzureADAuthTokenHandler(ILog log, IAzureADConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IAzureADKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }
    }
}