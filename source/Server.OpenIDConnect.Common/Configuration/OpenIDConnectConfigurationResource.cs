using System.ComponentModel;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;
using Octopus.Server.MessageContracts;
using Octopus.Server.MessageContracts.Attributes;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public class OpenIDConnectConfigurationResource : ExtensionConfigurationResource
    {
        [Description("Follow our documentation to find the Issuer for your identity provider")]
        public virtual string? Issuer { get; set; }

        [DisplayName("Client ID")]
        [Description("Octopus instances unique authentication id, as provided by your Octopus account")]
        public virtual string? ClientId { get; set; }

        [DisplayName("Client Secret")]
        [Description("Shared secret for validating the authentication tokens")]
        public virtual SensitiveValue? ClientSecret { get; set; }

        [DisplayName("Allow Auto User Creation")]
        [Description("Tell Octopus to automatically create a user account when a person signs in for the first time with this identity provider")]
        public virtual bool? AllowAutoUserCreation { get; set; }
    }
}