﻿using System.ComponentModel;
using Octopus.Data.Resources.Attributes;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration
{
    public class OpenIDConnectConfigurationResource : ExtensionConfigurationResource
    {
        [Description("Follow our documentation to find the Issuer for your identity provider")]
        [Writeable]
        public virtual string Issuer { get; set; }

        [DisplayName("Client ID")]
        [Description("Octopus instances unique authentication id, as provided by your Octopus account")]
        [Writeable]
        public virtual string ClientId { get; set; }

        [DisplayName("Allow Auto User Creation")]
        [Description("Tell Octopus to automatically create a user account when a person signs in for the first time with this identity provider")]
        [Writeable]
        public virtual bool? AllowAutoUserCreation { get; set; }
    }
}