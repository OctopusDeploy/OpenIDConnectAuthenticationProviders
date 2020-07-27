using Octopus.Data.Model;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public interface IOpenIDConnectConfigurationWithClientSecret : IOpenIDConnectConfiguration
    {
        SensitiveString? ClientSecret { get; set; }       
    }
}