using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities
{
    public abstract class IdentityCreator : IIdentityCreator
    {
        public const string ExternalIdClaimType = "eid";

        protected abstract string ProviderName { get; }

        public Identity Create(string? email, string? displayName, string? externalId)
        {
            var identity = new Identity(ProviderName);
            if (email != null)
                identity = identity.WithClaim(ClaimDescriptor.EmailClaimType, email, true);
            if (displayName != null)
                identity = identity.WithClaim(ClaimDescriptor.DisplayNameClaimType, displayName, false);
            if (externalId != null)
                identity = identity.WithClaim(ExternalIdClaimType, externalId, true, true);

            return identity;
        }
    }
}