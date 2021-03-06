using System.Security.Claims;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Infrastructure
{
    class AzureADPrincipalToUserResourceMapper : PrincipalToUserResourceMapper, IAzureADPrincipalToUserResourceMapper
    {
        protected override string? GetEmailAddress(ClaimsPrincipal principal)
        {
            // Grab the email address if it exists as a claim, otherwise get the UPN as a good fallback
            return base.GetEmailAddress(principal) ?? GetClaimValue(principal, ClaimTypes.Upn);
        }

        protected override string? GetUsername(ClaimsPrincipal principal)
        {
            // Use the UPN in preference for username
            return GetClaimValue(principal, ClaimTypes.Upn) ?? base.GetUsername(principal);
        }
    }
}