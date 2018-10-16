﻿using System.ComponentModel;
using Octopus.Client.Extensibility.Attributes;
using Octopus.Client.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Client.Extensibility.Authentication.Okta.Configuration
{
    [Description("Sign in to your Octopus Server with Okta. [Learn more](https://g.octopushq.com/AuthOkta).")]
    public class OktaConfigurationResource : OpenIDConnectConfigurationResource
    {
        public OktaConfigurationResource()
        {
            Id = "authentication-od";
        }

        [DisplayName("Role Claim Type")]
        [Description("Tell Octopus how to find the roles in the security token from Okta")]
        [Writeable]
        public string RoleClaimType { get; set; }
    }
}