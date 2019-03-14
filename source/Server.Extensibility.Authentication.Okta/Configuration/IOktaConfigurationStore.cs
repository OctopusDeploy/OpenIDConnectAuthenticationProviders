using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    public interface IOktaConfigurationStore : IOpenIDConnectConfigurationWithRoleStore<OktaConfiguration>
    {
        string GetUsernameClaimType();
        void SetUsernameClaimType(string usernameClaimType);
    }
}