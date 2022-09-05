using System.IO;
using Assent;
using Newtonsoft.Json;
using NUnit.Framework;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Tests.OpenIdConnect.Certificates
{
    [TestFixture]
    public class DefaultKeyJsonParserFixture
    {
        [Test]
        public void ShouldParseSupportedJwks_AzureAD()
        {
            // Source: https://login.microsoftonline.com/common/discovery/v2.0/keys
            var content = LoadJwksContent(nameof(ShouldParseSupportedJwks_AzureAD));

            var result = new DefaultKeyJsonParser().Parse(content);

            this.Assent(FormattedResult(result));
        }

        [Test]
        public void ShouldParseSupportedJwks_Google()
        {
            // Source: https://www.googleapis.com/oauth2/v3/certs
            var content = LoadJwksContent(nameof(ShouldParseSupportedJwks_Google));

            var result = new DefaultKeyJsonParser().Parse(content);

            this.Assent(FormattedResult(result));
        }

        [Test]
        public void ShouldParseSupportedJwks_Okta()
        {
            // Source: https://octopus-dev-roy.okta.com/oauth2/v1/keys
            var content = LoadJwksContent(nameof(ShouldParseSupportedJwks_Okta));

            var result = new DefaultKeyJsonParser().Parse(content);

            this.Assent(FormattedResult(result));
        }

        [Test]
        public void ShouldParseSupportedJwks_Ping()
        {
            // Source: https://secure.helpscout.net/conversation/1171176136/64935
            var content = LoadJwksContent(nameof(ShouldParseSupportedJwks_Ping));

            var result = new DefaultKeyJsonParser().Parse(content);

            this.Assent(FormattedResult(result));
        }

        static string FormattedResult(KeyDetails[] result)
        {
            return JsonConvert.SerializeObject(result, Formatting.Indented, new JsonSerializerSettings {TypeNameHandling = TypeNameHandling.All});
        }

        string LoadJwksContent(string testName)
        {
            var fixtureType = typeof(DefaultKeyJsonParserFixture);
            var resourceName = $"{fixtureType.FullName}.{testName}.jwks.json";
            using var s = fixtureType.Assembly.GetManifestResourceStream(resourceName);
            using var sr = new StreamReader(s);
            return sr.ReadToEnd();
        }
    }
}