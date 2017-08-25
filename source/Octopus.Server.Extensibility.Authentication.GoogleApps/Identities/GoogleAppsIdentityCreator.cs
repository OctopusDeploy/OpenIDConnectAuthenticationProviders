﻿using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Identities;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Identities
{
    public class GoogleAppsIdentityCreator : IdentityCreator, IGoogleAppsIdentityCreator
    {
        protected override string ProviderName => GoogleAppsAuthenticationProvider.ProviderName;
    }

    public interface IGoogleAppsIdentityCreator : IIdentityCreator
    { }
}