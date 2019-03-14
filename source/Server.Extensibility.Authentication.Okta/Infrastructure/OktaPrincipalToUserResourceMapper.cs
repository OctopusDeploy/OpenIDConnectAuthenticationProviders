using System.Security.Claims;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Infrastructure;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Infrastructure
{
    public class OktaPrincipalToUserResourceMapper : PrincipalToUserResourceMapper, IOktaPrincipalToUserResourceMapper
    {
        readonly IOktaConfigurationStore configurationStore;

        public OktaPrincipalToUserResourceMapper(IOktaConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        protected override string GetEmailAddress(ClaimsPrincipal principal)
        {
            // Grab the email address if it exists as a claim, otherwise get the UPN as a good fallback
            return base.GetEmailAddress(principal) ?? GetClaimValue(principal, ClaimTypes.Upn);
        }

        protected override string GetUsername(ClaimsPrincipal principal)
        {
            // Use the UPN in preference for username
            return GetClaimValue(principal, configurationStore.GetUsernameClaimType()) ?? base.GetUsername(principal);
        }
    }
}