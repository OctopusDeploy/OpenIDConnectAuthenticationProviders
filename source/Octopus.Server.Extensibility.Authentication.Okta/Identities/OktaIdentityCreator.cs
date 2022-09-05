using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.Model;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;

namespace Octopus.Server.Extensibility.Authentication.Okta.Identities
{
    class OktaIdentityCreator : IdentityCreator, IOktaIdentityCreator
    {
        public const string PreferredUsername = "pun";
        
        protected override string ProviderName => OktaAuthenticationProvider.ProviderName;

        public override Identity Create(UserResource userResource)
        {
            var identity = base.Create(userResource);
            if (userResource.Username != null && userResource.Username != userResource.EmailAddress && userResource.Username != userResource.ExternalId)
                identity = identity.WithClaim(PreferredUsername, userResource.Username, true);

            return identity;
        }
    }

    interface IOktaIdentityCreator : IIdentityCreator
    { }
}