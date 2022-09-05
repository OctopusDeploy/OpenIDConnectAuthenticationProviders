using System.Security.Claims;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public interface IPrincipalToUserResourceMapper
    {
        UserResource MapToUserResource(ClaimsPrincipal principal);
    }
}