﻿using System.ComponentModel;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    public class AzureADConfigurationResource : OpenIDConnectConfigurationResource
    {
        [DisplayName("Role Claim Type")]
        [Description("The type of the role claim")]
        public string RoleClaimType { get; set; }
    }
}