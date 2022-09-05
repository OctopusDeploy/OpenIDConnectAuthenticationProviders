using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Identities
{
    class GoogleAppsIdentityCreator : IdentityCreator, IGoogleAppsIdentityCreator
    {
        protected override string ProviderName => GoogleAppsAuthenticationProvider.ProviderName;
    }

    interface IGoogleAppsIdentityCreator : IIdentityCreator
    { }
}