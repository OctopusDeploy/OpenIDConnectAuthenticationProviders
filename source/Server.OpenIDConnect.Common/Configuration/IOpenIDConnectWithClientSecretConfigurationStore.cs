using Octopus.Data.Model;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public interface IOpenIDConnectWithClientSecretConfigurationStore<TConfiguration> : IOpenIDConnectConfigurationStore<TConfiguration>, IOpenIDConnectWithClientSecretConfigurationStore
        where TConfiguration : OpenIDConnectConfiguration, IId, new()
    {
    }

    public interface IOpenIDConnectWithClientSecretConfigurationStore : IOpenIDConnectConfigurationStore
    {
        SensitiveString? GetClientSecret();
        void SetClientSecret(SensitiveString? clientSecret);
    }
}