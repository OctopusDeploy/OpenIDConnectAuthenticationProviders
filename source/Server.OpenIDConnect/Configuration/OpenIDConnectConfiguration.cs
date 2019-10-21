﻿using Octopus.Data.Model;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration
{
    public abstract class OpenIDConnectConfiguration : ExtensionConfigurationDocument, IOverridableId, IOpenIDConnectConfiguration
    {
        public const string DefaultResponseType = "code+id_token";
        public const string DefaultResponseMode = "form_post";
        public const string DefaultScope = "openid%20profile%20email";
        public const string DefaultNameClaimType = "name";

        protected OpenIDConnectConfiguration()
        {
            AllowAutoUserCreation = true;
        }

        protected OpenIDConnectConfiguration(string name, string author, string configurationSchemaVersion) : base(name, author, configurationSchemaVersion)
        {
            Scope = DefaultScope;

            NameClaimType = DefaultNameClaimType;

            AllowAutoUserCreation = true;
        }

        public string Issuer { get; set; }

        public string ClientId { get; set; }

        public string Scope { get; set; }

        public string NameClaimType { get; set; }

        public bool AllowAutoUserCreation { get; set; }

        public void SetId(string id)
        {
            Id = id;
        }
    }
}