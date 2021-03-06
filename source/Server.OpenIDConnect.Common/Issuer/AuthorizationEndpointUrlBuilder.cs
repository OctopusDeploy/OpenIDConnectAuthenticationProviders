﻿using System;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.HostServices.Web;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer
{
    public abstract class AuthorizationEndpointUrlBuilder<TStore> : IAuthorizationEndpointUrlBuilder
        where TStore : IOpenIDConnectConfigurationStore
    {
        protected readonly TStore ConfigurationStore;
        readonly IUrlEncoder urlEncoder;

        protected AuthorizationEndpointUrlBuilder(TStore configurationStore, IUrlEncoder urlEncoder)
        {
            ConfigurationStore = configurationStore;
            this.urlEncoder = urlEncoder;
        }

        protected virtual string ResponseType => OpenIDConnectConfiguration.DefaultResponseType;
        protected virtual string ResponseMode => OpenIDConnectConfiguration.DefaultResponseMode;

        public virtual string Build(string requestDirectoryPath, IssuerConfiguration issuerConfiguration, string nonce, string? state = null)
        {
            if (issuerConfiguration == null)
                throw new ArgumentException("issuerConfiguration is required", nameof(issuerConfiguration));

            var issuerEndpoint = issuerConfiguration.AuthorizationEndpoint;
            var clientId = ConfigurationStore.GetClientId();
            var scope = ConfigurationStore.GetScope();
            var responseType = ResponseType;
            var responseMode = ResponseMode;
            var redirectUri = requestDirectoryPath.Trim('/') + ConfigurationStore.RedirectUri;

            var url = $"{issuerEndpoint}?client_id={clientId}&scope={scope}&response_type={responseType}&response_mode={responseMode}&nonce={nonce}&redirect_uri={redirectUri}";
            
            if (!string.IsNullOrWhiteSpace(state))
            {
                url += $"&state={urlEncoder.UrlEncode(state)}";
            }

            return url;
        }
    }
}