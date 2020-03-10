﻿using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    class OctopusIDConfiguration : OpenIDConnectConfigurationWithClientSecret, IOpenIDConnectConfigurationWithRole
    {
        public static string DefaultRoleClaimType = "roles";

        public OctopusIDConfiguration() : base("OctopusID", "Octopus Deploy", "1.1")
        {
            Id = OctopusIDConfigurationStore.SingletonId;
            Issuer = "https://account.octopus.com";
            Scope = DefaultScope;
            RoleClaimType = DefaultRoleClaimType;
        }
        
        public string RoleClaimType { get; set; }
    }
}