using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.GraphApi
{
    internal class GraphApiClient
    {
        private readonly HttpClient httpClient;
        private readonly Uri tokenUri;
        private readonly Guid clientId;
        private readonly string clientSecret;

        private const string scope = "https://graph.microsoft.com/groupmember.read.all";
        private const string grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
        private const string requestedTokenUse = "on_behalf_of";
        private const string graphQuerySelect = "$select=id,displayName,onPremisesNetBiosName,onPremisesDomainName,onPremisesSamAccountNameonPremisesSecurityIdentifier";

        public GraphApiClient(HttpClient httpClient, Guid tenantId, Guid clientId, string? clientSecret)
        {
            this.httpClient = httpClient;
            tokenUri = new Uri("https://login.microsoftonline.com/" + tenantId.ToString() + "/oauth2/v2.0/token");
            this.clientId = clientId;
            this.clientSecret = clientSecret ?? throw new ArgumentNullException(nameof(clientSecret));
        }

        public async Task<string> GetAccessTokenOnBehalfOfUser(string assertion)
        {
            var requestBody = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", grantType),
                new KeyValuePair<string, string>("client_id", clientId.ToString()),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("assertion", assertion),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("requested_token_use", requestedTokenUse)
            });

            var response = await httpClient.PostAsync(tokenUri, requestBody);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            var model = JsonConvert.DeserializeObject<TokenResponse>(responseBody);

            return model.AccessToken;
        }

        public async Task<string[]> GetGroupMembershipIds(string accessToken)
        {
            var groups = new HashSet<string>();
            string? nextLink = null;
            do
            {
                var uri = string.IsNullOrEmpty(nextLink) ? ("https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.group?" + graphQuerySelect) : nextLink;
                // The nextLink will contain all other query parameters from original request: https://docs.microsoft.com/en-us/graph/paging?context=graph%2Fapi%2F1.0&view=graph-rest-1.0
                using (var request = new HttpRequestMessage(HttpMethod.Get, uri))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                    var response = await httpClient.SendAsync(request);
                    response.EnsureSuccessStatusCode();
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var graphObjects = JsonConvert.DeserializeObject<GraphResponse>(responseBody);
                    nextLink = graphObjects.NextLink;

                    groups.UnionWith(graphObjects.Value.Select(m => m.Id));
                }
            } while (!string.IsNullOrEmpty(nextLink));

            return groups.ToArray();
        }
    }
}
