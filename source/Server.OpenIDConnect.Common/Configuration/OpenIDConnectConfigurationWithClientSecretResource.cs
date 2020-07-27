using System.ComponentModel;
using Octopus.Data.Resources;
using Octopus.Data.Resources.Attributes;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public class OpenIDConnectConfigurationWithClientSecretResource : OpenIDConnectConfigurationResource
    {
        [DisplayName("Client Secret")]
        [Description("Shared secret for validating the authentication tokens")]
        [Writeable]
        public virtual SensitiveValue? ClientSecret { get; set; }
    }
}