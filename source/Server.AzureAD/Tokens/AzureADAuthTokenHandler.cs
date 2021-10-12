using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.AzureAD.GraphApi;
using Octopus.Server.Extensibility.Authentication.AzureAD.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Tokens
{
    class AzureADAuthTokenHandler : OpenIDConnectAuthTokenWithRolesHandler<IAzureADConfigurationStore, IAzureADKeyRetriever, IIdentityProviderConfigDiscoverer>, IAzureADAuthTokenHandler
    {
        private readonly IAzureADConfigurationStore configurationStore;
        private const string graphQuerySelect = "id,displayName,onPremisesNetBiosName,onPremisesDomainName,onPremisesSamAccountNameonPremisesSecurityIdentifier";

        public AzureADAuthTokenHandler(ISystemLog log, IAzureADConfigurationStore configurationStore, IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer, IAzureADKeyRetriever keyRetriever) : base(log, configurationStore, identityProviderConfigDiscoverer, keyRetriever)
        {
            this.configurationStore = configurationStore;
        }

        protected override string[] GetProviderGroupIds(ClaimsPrincipal principal, string? assertion = null)
            => (SupportsHandlingOverages() && HasOverageOccurred(principal))
                ? GetProviderGroupIdsAsync(principal, assertion).Result
                : base.GetProviderGroupIds(principal);

        private async Task<string[]> GetProviderGroupIdsAsync(ClaimsPrincipal principal, string? idToken)
        {
            var groups = new HashSet<string>();
            using (var httpClient = new HttpClient())
            {
                var graphClient = new GraphApiClient(
                    httpClient,
                    GetTenantIdFromIssuer(configurationStore.GetIssuer()),
                    Guid.Parse(configurationStore.GetClientId()),
                    configurationStore.GetClientSecret()?.Value
                );
                var bearerToken = await graphClient.GetAccessTokenOnBehalfOfUser(idToken);
                // todo: Call Graph API to get group membership

                return groups.ToArray();
            }
        }

        private bool SupportsHandlingOverages() => !string.IsNullOrEmpty(configurationStore.GetClientSecret()?.Value);

        private static bool HasOverageOccurred(ClaimsPrincipal identity) => identity.Claims.Any(x => x.Type == "hasgroups" || (x.Type == "_claim_names" && x.Value == "{\"groups\":\"src1\"}"));

        private static Guid GetTenantIdFromIssuer(string? issuer)
        {
            var uri = new Uri(issuer);
            return Guid.Parse(uri.Segments.Last());
        }
    }
}