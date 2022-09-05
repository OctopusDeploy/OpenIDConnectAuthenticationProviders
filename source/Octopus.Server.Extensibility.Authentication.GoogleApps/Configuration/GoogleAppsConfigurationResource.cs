using System.ComponentModel;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.MessageContracts.Attributes;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    [Description("Sign in to your Octopus Server with Google Apps. [Learn more](https://g.octopushq.com/AuthGoogleApps).")]
    class GoogleAppsConfigurationResource : OpenIDConnectConfigurationResource
    {
        [DisplayName("Hosted Domain")]
        [Description("Tell Octopus which Google Apps domain to trust")]
        [Writeable]
        public string? HostedDomain { get; set; }
    }
}