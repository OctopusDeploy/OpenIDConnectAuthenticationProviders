using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.Identities;
using Octopus.Server.Extensibility.Authentication.AzureAD.Infrastructure;
using Octopus.Server.Extensibility.Authentication.AzureAD.Tokens;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Web
{
    class AzureADUserAuthenticatedPkceAction : UserAuthenticatedPkceAction<IAzureADConfigurationStore, IAzureADAuthTokenHandler, IAzureADIdentityCreator>
    {
        public AzureADUserAuthenticatedPkceAction(
            ISystemLog log,
            IAzureADAuthTokenHandler authTokenHandler,
            IAzureADPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            IAzureADConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IAzureADIdentityCreator identityCreator,
            IClock clock,
            IUrlEncoder encoder,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IMediator mediator) :
            base(
                log,
                authTokenHandler,
                principalToUserResourceMapper,
                userStore,
                configurationStore,
                authCookieCreator,
                loginTracker,
                sleep,
                identityCreator,
                clock,
                encoder,
                identityProviderConfigDiscoverer, mediator)
        {
        }

        protected override string ProviderName => AzureADAuthenticationProvider.ProviderName;
    }
}