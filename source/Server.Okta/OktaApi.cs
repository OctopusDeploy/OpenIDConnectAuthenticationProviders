﻿using System;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Identities;
using Octopus.Server.Extensibility.Authentication.Okta.Tokens;
using Octopus.Server.Extensibility.Authentication.Okta.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.Okta
{
    class OktaApi : OpenIDConnectModule<OktaUserAuthenticationAction, IOktaConfigurationStore, OktaUserAuthenticatedAction, IOktaAuthTokenHandler, IOktaIdentityCreator>
    {
        public OktaApi(IOktaConfigurationStore configurationStore, OktaAuthenticationProvider authenticationProvider)
            : base(configurationStore, authenticationProvider)
        {
            Add<OktaUserAuthenticationAction>("POST", authenticationProvider.AuthenticateUri, RouteCategory.Navigable, new AnonymousWhenEnabledEndpointInvocation<IOktaConfigurationStore>());
            Add<OktaUserAuthenticatedAction>("POST", configurationStore.RedirectUri, RouteCategory.Navigable, new AnonymousWhenEnabledEndpointInvocation<IOktaConfigurationStore>());
        }
    }
}