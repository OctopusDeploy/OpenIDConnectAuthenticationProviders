using Octopus.Data.Model.User;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities
{
    public interface IIdentityCreator
    {
        Identity Create(string? email, string? displayName, string? externalId);
    }
}