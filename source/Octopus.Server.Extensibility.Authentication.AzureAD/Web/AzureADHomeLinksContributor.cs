using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Web
{
    class AzureADHomeLinksContributor : OpenIDConnectHomeLinksContributor<IAzureADConfigurationStore, AzureADAuthenticationProvider>
    {
        public AzureADHomeLinksContributor(IAzureADConfigurationStore configurationStore, AzureADAuthenticationProvider authenticationProvider) : base(configurationStore, authenticationProvider)
        {
        }
    }
}