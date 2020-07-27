using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates
{
    public class DefaultKeyJsonParser : IKeyJsonParser
    {
        /// <summary>
        /// https://tools.ietf.org/html/rfc7517#section-4.1
        /// </summary>
        const string RsaKeyType = "RSA";

        public KeyDetails[] Parse(string content)
        {
            var keyData = JsonConvert.DeserializeObject<IssuerKeys>(content);

            return keyData.Keys
                .Where(IsRsaKey)
                .Select(ConvertIssuerKeyToDetails)
                .ToArray();
        }

        bool IsRsaKey(IssuerKey key)
        {
            return key.KeyType == RsaKeyType;
        }

        static KeyDetails ConvertIssuerKeyToDetails(IssuerKey key)
        {
            if (key.x509Chain != null && key.x509Chain.Any())
            {
                return new CertificateDetails
                {
                    Kid = key.KeyId,
                    Certificate = key.x509Chain.First()
                };
            }

            if (key.Exponent == null || key.Modulus == null)
                throw new UnsupportedJsonWebKeyFormatException($"Failed to parse JSON Web Key (\"kid\": \"{key.KeyId}\"): expected an RSA key with X.509 Certificate Chain, or exponent and modulus.");

            return new RsaDetails
            {
                Kid = key.KeyId,
                Exponent = key.Exponent,
                Modulus = key.Modulus
            };
        }

        public class IssuerKeys
        {
            public List<IssuerKey> Keys { get; set; } = new List<IssuerKey>();
        }

        public class IssuerKey
        {
            [JsonProperty("kty")]
            public string KeyType { get; set; } = string.Empty;

            [JsonProperty("use")]
            public string PublicKeyUse { get; set; } = string.Empty;

            [JsonProperty("kid")]
            public string KeyId { get; set; } = string.Empty;

            [JsonProperty("e")]
            public string? Exponent { get; set; }

            [JsonProperty("n")]
            public string? Modulus { get; set; }

            [JsonProperty("x5c")]
            public string[]? x509Chain { get; set; }
        }
    }
}