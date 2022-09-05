using System.ComponentModel;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.MessageContracts.Attributes;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    [Description("Sign in to your Octopus Server with Okta. [Learn more](https://g.octopushq.com/AuthOkta).")]
    class OktaConfigurationResource : OpenIDConnectConfigurationResource
    {
        [DisplayName("Role Claim Type")]
        [Description("Tell Octopus how to find the roles in the security token from Okta")]
        [Writeable]
        public string? RoleClaimType { get; set; }

        [DisplayName("Username Claim Type")]
        [Description("Tell Octopus how to find the value for the Octopus Username in the Okta token. Defaults to \"preferred_username\" if left blank.")]
        [Writeable]
        public string? UsernameClaimType { get; set; }
    }
}