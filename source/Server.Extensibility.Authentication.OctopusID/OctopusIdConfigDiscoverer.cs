using System.Threading.Tasks;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    public class OctopusIdConfigDiscoverer : IIdentityProviderConfigDiscoverer
    {
        public Task<IssuerConfiguration> GetConfigurationAsync(string issuer)
        {
            return Task.FromResult(new IssuerConfiguration()
            {
                Issuer = issuer + "/", // NOTE: the trailing / is important!
                AuthorizationEndpoint = issuer + "/oauth2/authorize"
            });
        }
    }
}