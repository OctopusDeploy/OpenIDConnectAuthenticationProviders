using System.ComponentModel;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.MessageContracts;
using Octopus.Server.MessageContracts.Attributes;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    [Description("Sign in to your Octopus Server with an Octopus ID. [Learn more](https://g.octopushq.com/AuthOctopusID).")]
    class OctopusIDConfigurationResource : OpenIDConnectConfigurationWithClientSecretResource
    {
        [ReadOnly(true)]
        public override string? Issuer { get; set; }

        [ReadOnly(true)]
        public override bool? AllowAutoUserCreation { get; set; }
    }
}