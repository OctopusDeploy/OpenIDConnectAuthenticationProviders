using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.Model;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities
{
    public abstract class IdentityCreator : IIdentityCreator
    {
        public const string ExternalIdClaimType = "eid";

        protected abstract string ProviderName { get; }

        public virtual Identity Create(UserResource userResource)
        {
            var identity = new Identity(ProviderName);
            if (userResource.EmailAddress != null)
                identity = identity.WithClaim(ClaimDescriptor.EmailClaimType, userResource.EmailAddress, true);
            if (userResource.DisplayName != null)
                identity = identity.WithClaim(ClaimDescriptor.DisplayNameClaimType, userResource.DisplayName, false);
            if (userResource.ExternalId != null)
                identity = identity.WithClaim(ExternalIdClaimType, userResource.ExternalId, true, true);

            return identity;
        }
    }
}