using Octopus.Data.Model;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public interface IOpenIDConnectConfigurationWithRoleStore<TConfiguration> : IOpenIDConnectConfigurationStore<TConfiguration>, IOpenIDConnectConfigurationWithRoleStore
        where TConfiguration : ExtensionConfigurationDocument, IOpenIDConnectConfigurationWithRole, IId, new()
    {
    }

    public interface IOpenIDConnectConfigurationWithRoleStore : IOpenIDConnectConfigurationStore
    {
        string? GetRoleClaimType();
        void SetRoleClaimType(string? roleClaimType);
    }
}