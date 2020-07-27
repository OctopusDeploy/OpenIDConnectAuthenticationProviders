namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class OpenIDConnectConfigurationWithRole : OpenIDConnectConfiguration, IOpenIDConnectConfigurationWithRole
    {
        protected OpenIDConnectConfigurationWithRole(string id) : base(id)
        {
        }

        protected OpenIDConnectConfigurationWithRole(string id, string name, string author, string configurationSchemaVersion) : base(id, name, author, configurationSchemaVersion)
        {
        }

        public string? RoleClaimType { get; set; }
    }
}