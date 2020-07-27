using System;
using System.Security.Claims;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens
{
    public class ClaimsPrincipleContainer
    {
        public ClaimsPrincipleContainer(string error)
        {
            this.Error = error;
            ExternalGroupIds = Array.Empty<string>();
        }
        public ClaimsPrincipleContainer(ClaimsPrincipal principal, string[] externalGroupIds)
        {
            this.Principal = principal;
            ExternalGroupIds = externalGroupIds;
        }

        public string? Error { get; }
        public ClaimsPrincipal? Principal { get; }

        /// <summary>
        /// Gets or sets the external Role/Group Ids
        /// </summary>
        public string[] ExternalGroupIds { get; }
    }
}
