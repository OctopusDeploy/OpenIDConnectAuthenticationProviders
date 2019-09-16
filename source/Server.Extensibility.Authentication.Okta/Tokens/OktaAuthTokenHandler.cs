using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.Okta.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Tokens;

namespace Octopus.Server.Extensibility.Authentication.Okta.Tokens
{
    public class OktaAuthTokenHandler : OpenIDConnectAuthTokenWithRolesHandler<IOktaConfigurationStore, IOktaKeyRetriever, IIdentityProviderConfigDiscoverer>, IOktaAuthTokenHandler
    {
        public OktaAuthTokenHandler(ILog log, IOktaConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IOktaKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
        }
    }
}