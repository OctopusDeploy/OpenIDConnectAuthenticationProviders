using Octopus.Data.Model;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIDConnectConfigurationWithClientSecret : OpenIDConnectConfiguration, IOpenIDConnectConfigurationWithClientSecret
    {
        protected OpenIDConnectConfigurationWithClientSecret(string id) : base(id)
        {
        }

        protected OpenIDConnectConfigurationWithClientSecret(string id, string name, string author, string configurationSchemaVersion) : base(id, name, author, configurationSchemaVersion)
        {
        }

        public SensitiveString? ClientSecret { get; set; }
    }
}