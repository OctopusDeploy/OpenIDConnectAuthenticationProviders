using Octopus.Data.Model.User;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities
{
    public interface IIdentityCreator
    {
        Identity Create(UserResource userResource);
    }
}