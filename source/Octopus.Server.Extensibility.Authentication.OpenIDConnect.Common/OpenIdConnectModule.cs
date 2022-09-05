using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common
{
    public abstract class OpenIDConnectModule<TAuthenticationAction, TStore, TAuthenticatedAction, TAuthTokenHandler, TIdentityCreator> : RegistersEndpoints
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthenticationAction : UserAuthenticationAction<TStore>
        where TAuthTokenHandler : IAuthTokenHandler
        where TAuthenticatedAction : UserAuthenticatedAction<TStore, TAuthTokenHandler, TIdentityCreator>
        where TIdentityCreator : IIdentityCreator
    {
        protected OpenIDConnectModule(TStore configurationStore, IAuthenticationProvider authenticationProvider)
        {
        }
    }
}