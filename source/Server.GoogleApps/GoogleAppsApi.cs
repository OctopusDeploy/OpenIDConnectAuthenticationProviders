﻿using System;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Identities;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Tokens;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Web;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps
{
    class GoogleAppsApi : OpenIDConnectModule<GoogleAppsUserAuthenticationAction, IGoogleAppsConfigurationStore, GoogleAppsUserAuthenticatedAction, IGoogleAuthTokenHandler, IGoogleAppsIdentityCreator>
    {
        public GoogleAppsApi(
            IGoogleAppsConfigurationStore configurationStore, GoogleAppsAuthenticationProvider authenticationProvider)
            : base(configurationStore, authenticationProvider)
        {
            Add<GoogleAppsUserAuthenticationAction>("POST", authenticationProvider.AuthenticateUri, RouteCategory.Navigable, new AnonymousWhenEnabledEndpointInvocation<IGoogleAppsConfigurationStore>());
            Add<GoogleAppsUserAuthenticatedAction>("POST", configurationStore.RedirectUri, RouteCategory.Navigable, new AnonymousWhenEnabledEndpointInvocation<IGoogleAppsConfigurationStore>());
        }
    }
}