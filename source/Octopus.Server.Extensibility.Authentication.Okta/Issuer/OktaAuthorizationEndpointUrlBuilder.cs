using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.Okta.Issuer
{
    class OktaAuthorizationEndpointUrlBuilder : AuthorizationEndpointUrlBuilder<IOktaConfigurationStore>, IOktaAuthorizationEndpointUrlBuilder
    {
        public OktaAuthorizationEndpointUrlBuilder(IOktaConfigurationStore configurationStore, IUrlEncoder urlEncoder) : base(configurationStore, urlEncoder)
        {
        }
    }
}