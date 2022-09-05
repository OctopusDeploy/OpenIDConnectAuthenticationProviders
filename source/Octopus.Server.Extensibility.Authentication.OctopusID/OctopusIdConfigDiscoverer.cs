using System.Threading.Tasks;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    class OctopusIdConfigDiscoverer : IOctopusIdentityProviderConfigDiscoverer
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