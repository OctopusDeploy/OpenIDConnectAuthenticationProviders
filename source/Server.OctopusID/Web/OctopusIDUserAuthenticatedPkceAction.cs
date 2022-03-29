using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OctopusID.Identities;
using Octopus.Server.Extensibility.Authentication.OctopusID.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    class OctopusIDUserAuthenticatedPkceAction
        : UserAuthenticatedPkceAction<IOctopusIDConfigurationStore, IOctopusIDAuthTokenHandler, IOctopusIDIdentityCreator>
    {
        public OctopusIDUserAuthenticatedPkceAction(
            ISystemLog log,
            IOctopusIDAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            IUpdateableUserStore userStore,
            IOctopusIDConfigurationStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            IOctopusIDIdentityCreator identityCreator,
            IClock clock, IUrlEncoder encoder, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IMediator mediator)
            : base(log, authTokenHandler, principalToUserResourceMapper, userStore, configurationStore, authCookieCreator, loginTracker, sleep, identityCreator, clock, encoder, identityProviderConfigDiscoverer, mediator)
        {
        }

        protected override string ProviderName => OctopusIDAuthenticationProvider.ProviderName;
    }
}