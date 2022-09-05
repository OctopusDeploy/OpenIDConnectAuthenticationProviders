using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    class OctopusIDHomeLinksContributor : OpenIDConnectHomeLinksContributor<IOctopusIDConfigurationStore, OctopusIDAuthenticationProvider>
    {
        public OctopusIDHomeLinksContributor(IOctopusIDConfigurationStore configurationStore, OctopusIDAuthenticationProvider authenticationProvider) : base(configurationStore, authenticationProvider)
        {
        }
    }
}