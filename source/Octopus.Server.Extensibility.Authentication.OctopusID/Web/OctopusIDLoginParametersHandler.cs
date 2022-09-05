using System;
using System.Linq;
using Octopus.Server.Extensibility.Authentication.Extensions;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.Web;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Web
{
    class OctopusIDLoginParametersHandler : ICanHandleLoginParameters
    {
        readonly IOctopusIDConfigurationStore configurationStore;

        public OctopusIDLoginParametersHandler(IOctopusIDConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        public string IdentityProviderName => OctopusIDAuthenticationProvider.ProviderName;

        public bool? WasExternalLoginInitiated(string encodedQueryString)
        {
            if (!configurationStore.GetIsEnabled())
                return null;

            var parser = new EncodedQueryStringParser();
            var parameters = parser.Parse(encodedQueryString);

            var issuerParam = parameters.FirstOrDefault(p => p.Name == "iss");

            var configuredIssuer = configurationStore.GetIssuer();

            return issuerParam != null && string.Compare(configuredIssuer, issuerParam.Value, StringComparison.InvariantCultureIgnoreCase) == 0;
        }
    }
}