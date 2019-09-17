﻿using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    public class OctopusIDUserAuthenticationAction : UserAuthenticationAction<IOctopusIDConfigurationStore>
    {
        public OctopusIDUserAuthenticationAction(
            ILog log,
            IOctopusIDConfigurationStore configurationStore, 
            IOctopusIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, 
            IOctopusIDAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore) : base(log, configurationStore, identityProviderConfigDiscoverer, urlBuilder, modelBinder, authenticationConfigurationStore)
        {
        }
    }
}