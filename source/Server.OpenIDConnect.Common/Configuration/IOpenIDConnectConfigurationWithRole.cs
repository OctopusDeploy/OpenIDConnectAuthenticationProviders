namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public interface IOpenIDConnectConfigurationWithRole : IOpenIDConnectConfiguration
    {
        string? RoleClaimType { get; set; }       
    }
}