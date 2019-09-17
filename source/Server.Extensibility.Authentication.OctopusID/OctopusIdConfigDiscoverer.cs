using System.Threading.Tasks;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    public class OctopusIdConfigDiscoverer : IOctopusIdentityProviderConfigDiscoverer
    {
        public Task<IssuerConfiguration> GetConfigurationAsync(string issuer)
        {
            return Task.FromResult(new IssuerConfiguration
            {
                Issuer = issuer.WithTrailingSlash(),
                AuthorizationEndpoint = $"{issuer.WithoutTrailingSlash()}/oauth2/authorize"
            });
        }
    }
}