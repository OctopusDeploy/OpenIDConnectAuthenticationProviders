using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Issuer
{
    class AzureADAuthorizationEndpointUrlBuilder : AuthorizationEndpointUrlBuilder<IAzureADConfigurationStore>, IAzureADAuthorizationEndpointUrlBuilder
    {
        public AzureADAuthorizationEndpointUrlBuilder(IAzureADConfigurationStore configurationStore, IUrlEncoder urlEncoder) : base(configurationStore, urlEncoder)
        {
        }
    }
}