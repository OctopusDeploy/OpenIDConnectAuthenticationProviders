using System;
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

        /// <summary>
        /// https://tools.ietf.org/html/rfc7517#section-4.2
        /// </summary>
        const string Signature = "sig";

        public KeyDetails[] Parse(string content)
        {
            var keyData = JsonConvert.DeserializeObject<IssuerKeys>(content);

            return keyData.Keys
                .Where(IsRsaKeyForSigning)
                .Select(ConvertIssuerKeyToDetails)
                .ToArray();
        }

        bool IsRsaKeyForSigning(IssuerKey key)
        {
            return key.KeyType == RsaKeyType && key.PublicKeyUse == Signature;
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

            return new RsaDetails
            {
                Kid = key.KeyId,
                Exponent = key.Exponent,
                Modulus = key.Modulus
            };
        }

        public class IssuerKeys
        {
            public List<IssuerKey> Keys { get; set; }
        }

        public class IssuerKey
        {
            [JsonProperty("kty")]
            public string KeyType { get; set; }

            [JsonProperty("use")]
            public string PublicKeyUse { get; set; }

            [JsonProperty("kid")]
            public string KeyId { get; set; }

            [JsonProperty("e")]
            public string Exponent { get; set; }
            [JsonProperty("n")]
            public string Modulus { get; set; }

            [JsonProperty("x5c")]
            public string[] x509Chain { get; set; }
        }
    }
}