using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticationAction<TStore> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
    {
        readonly ILog log;
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        readonly IAuthorizationEndpointUrlBuilder urlBuilder;

        protected readonly TStore ConfigurationStore;
        readonly IApiActionModelBinder modelBinder;
        readonly IAuthenticationConfigurationStore authenticationConfigurationStore;

        protected UserAuthenticationAction(
            ILog log,
            TStore configurationStore,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IAuthorizationEndpointUrlBuilder urlBuilder,
            IApiActionModelBinder modelBinder,
            IAuthenticationConfigurationStore authenticationConfigurationStore)
        {
            this.log = log;
            this.modelBinder = modelBinder;
            this.authenticationConfigurationStore = authenticationConfigurationStore;
            ConfigurationStore = configurationStore;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.urlBuilder = urlBuilder;
        }

        public async Task<OctoResponse> ExecuteAsync(IOctoRequest request)
        {
            if (ConfigurationStore.GetIsEnabled() == false)
            {
                log.Warn($"{ConfigurationStore.ConfigurationSettingsName} user authentication API was called while the provider was disabled.");
                return new OctoBadRequestResponse("This authentication provider is disabled.");
            }

            var model = modelBinder.Bind<LoginRedirectLinkRequestModel>();

            // If the login state object was passed use it, otherwise fall back to a safe default:
            //   1. Redirecting to the root of the local web site
            //   2. Setting the Cookie.Secure flag according to the current request
            var state = model.State ?? new LoginState{RedirectAfterLoginTo = "/", UsingSecureConnection = request.IsHttps};

            // Prevent Open Redirection attacks by ensuring the redirect after successful login is somewhere we trust (local origin or a trusted remote origin)
            var whitelist = authenticationConfigurationStore.GetTrustedRedirectUrls();
            if (!Requests.IsLocalUrl(state.RedirectAfterLoginTo, whitelist))
            {
                log.WarnFormat("Prevented potential Open Redirection attack on an authentication request, to the non-local url {0}", state.RedirectAfterLoginTo);
                return new OctoBadRequestResponse("Request not allowed, due to potential Open Redirection attack");
            }

            // Finally, provide the client with the information it requires to initiate the redirect to the external identity provider
            try
            {
                var issuer = ConfigurationStore.GetIssuer();
                var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(issuer);

                // Use a non-deterministic nonce to prevent replay attacks
                var nonce = Nonce.GenerateUrlSafeNonce();

                var stateString = JsonConvert.SerializeObject(state);
                var url = urlBuilder.Build(model.ApiAbsUrl, issuerConfig, nonce, stateString);

                // These cookies are used to validate the data returned from the external identity provider - this prevents tampering
                return new OctoDataResponse(new LoginRedirectLinkResponseModel {ExternalAuthenticationUrl = url})
                    .WithCookie(new OctoCookie {Name = UserAuthConstants.OctopusStateCookieName, Value = State.Protect(stateString), HttpOnly = true, Secure = state.UsingSecureConnection, Expires = DateTimeOffset.UtcNow.AddMinutes(20)})
                    .WithCookie(new OctoCookie {Name = UserAuthConstants.OctopusNonceCookieName, Value = Nonce.Protect(nonce), HttpOnly = true, Secure = state.UsingSecureConnection, Expires = DateTimeOffset.UtcNow.AddMinutes(20)});
            }
            catch (ArgumentException ex)
            {
                log.Error(ex);
                return new OctoBadRequestResponse(ex.Message);
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return new OctoBadRequestResponse("Login failed. Please see the Octopus Server logs for more details.");
            }
        }
    }
}