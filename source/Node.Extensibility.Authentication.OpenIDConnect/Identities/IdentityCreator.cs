using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.Resources.Identities;

namespace Octopus.Node.Extensibility.Authentication.OpenIDConnect.Identities
{
    public abstract class IdentityCreator : IIdentityCreator
    {
        public const string ExternalIdClaimType = "eid";

        protected abstract string ProviderName { get; }

        public Identity Create(string email, string displayName, string externalId)
        {
            return new Identity(ProviderName)
                .WithClaim(ClaimDescriptor.EmailClaimType, email, true)
                .WithClaim(ClaimDescriptor.DisplayNameClaimType, displayName, false)
                .WithClaim(ExternalIdClaimType, externalId, true, true);
        }
    }
}