using System.Threading.Tasks;
using NUnit.Framework;
using Octopus.Server.Extensibility.Authentication.OctopusID;

namespace Tests.OctopusID
{
    [TestFixture]
    public class OctopusIdConfigDiscovererFixture
    {
        [Test]
        [TestCase("https://someissuer/", "https://someissuer/", "https://someissuer/oauth2/authorize")]
        [TestCase("https://someissuer", "https://someissuer/", "https://someissuer/oauth2/authorize")]
        public async Task ShouldHandleTrailingSlashes(string inputIssuer, string expectedOutputIssuer, string expectedAuthorizationEndpoint)
        {
            var sut = new OctopusIdConfigDiscoverer();

            var result = await sut.GetConfigurationAsync(inputIssuer);

            Assert.AreEqual(expectedOutputIssuer, result.Issuer);
            Assert.AreEqual(expectedAuthorizationEndpoint, result.AuthorizationEndpoint);
        }
    }
}