using Octopus.Data.Model;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public interface IOpenIDConnectConfigurationStore<TConfiguration> : IExtensionConfigurationStore<TConfiguration>, IOpenIDConnectConfigurationStore
        where TConfiguration : ExtensionConfigurationDocument, IOpenIDConnectConfiguration, IId, new()
    {
    }

    public interface IOpenIDConnectConfigurationStore : IExtensionConfigurationStore
    {
        string ConfigurationSettingsName { get; }

        string? GetIssuer();
        void SetIssuer(string? issuer);

        string? GetClientId();
        void SetClientId(string? clientId);

        string? GetScope();
        void SetScope(string? scope);

        string? GetNameClaimType();
        void SetNameClaimType(string? nameClaimType);

        string RedirectUri { get; }

        bool GetAllowAutoUserCreation();
        void SetAllowAutoUserCreation(bool allowAutoUserCreation);
    }
}