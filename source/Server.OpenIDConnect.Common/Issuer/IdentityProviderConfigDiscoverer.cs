using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer
{
    public class IdentityProviderConfigDiscoverer : IIdentityProviderConfigDiscoverer
    {
        readonly Dictionary<string, IssuerConfiguration> configurations = new Dictionary<string, IssuerConfiguration>();

        public async Task<IssuerConfiguration> GetConfiguration(string issuer)
        {
            if (configurations.ContainsKey(issuer))
                return configurations[issuer];

            IssuerConfiguration configuration;

            using (var client = new HttpClient())
            {
                var response = await client.GetAsync(issuer + "/.well-known/openid-configuration");
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new ArgumentException($"The identity provider's well-known configuration cannot be read. This is possibly due to a misconfiguration of the issuer ({issuer}).");

                var content = await response.Content.ReadAsStringAsync();

                configuration = JsonConvert.DeserializeObject<IssuerConfiguration>(content);
                if (configuration == null)
                    throw new Exception($"The identity provider's well-known configuration cannot be deserialized. This is possibly due to a misconfiguration of the issuer ({issuer}).");
            }

            configurations.Add(issuer, configuration);

            return configuration;
        }
    }
}