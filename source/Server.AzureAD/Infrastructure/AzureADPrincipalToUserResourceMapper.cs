using System;
using System.Security.Claims;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Infrastructure
{
    class AzureADPrincipalToUserResourceMapper : PrincipalToUserResourceMapper, IAzureADPrincipalToUserResourceMapper
    {
        protected override string? GetEmailAddress(ClaimsPrincipal principal) =>
            // Grab the email address if it exists as a claim, otherwise get the UPN as a good fallback
            base.GetEmailAddress(principal) ?? GetClaimValue(principal, ClaimTypes.Upn);

        protected override string? GetUsername(ClaimsPrincipal principal) =>
            // Use the UPN in preference for username
            GetClaimValue(principal, ClaimTypes.Upn) ?? base.GetUsername(principal);
    }
}
