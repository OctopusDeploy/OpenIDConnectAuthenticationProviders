using System.Collections.Generic;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class OpenIDConnectHomeLinksContributor<TStore, TAuthenticationProvider> : IHomeLinksContributor
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthenticationProvider : OpenIDConnectAuthenticationProvider<TStore>
    {
        readonly TStore configurationStore;
        readonly TAuthenticationProvider authenticationProvider;

        protected OpenIDConnectHomeLinksContributor(TStore configurationStore, TAuthenticationProvider authenticationProvider)
        {
            this.configurationStore = configurationStore;
            this.authenticationProvider = authenticationProvider;
        }

        public IDictionary<string,string> GetLinksToContribute()
        {
            var linksToContribute = new Dictionary<string, string>();

            if (configurationStore.GetIsEnabled())
            {
                linksToContribute.Add("Authenticate_" + authenticationProvider.IdentityProviderName, "~" + authenticationProvider.AuthenticateUri + "{?returnUrl}");
            }

            return linksToContribute;
        }
    }
}