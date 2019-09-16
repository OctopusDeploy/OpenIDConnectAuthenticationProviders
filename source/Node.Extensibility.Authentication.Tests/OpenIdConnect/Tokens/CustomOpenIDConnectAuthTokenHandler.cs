using Octopus.Diagnostics;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Certificates;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Configuration;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Tokens;

namespace Node.Extensibility.Authentication.Tests.OpenIdConnect.Tokens
{
    public class CustomOpenIDConnectAuthTokenHandler : OpenIDConnectAuthTokenHandler<IOpenIDConnectConfigurationStore, IKeyRetriever, IIdentityProviderConfigDiscoverer>
    { 
        public CustomOpenIDConnectAuthTokenHandler(ILog log, IOpenIDConnectConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
            
        }
    }
}
