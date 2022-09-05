using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates
{
    public interface IKeyRetriever
    {
        Task<IDictionary<string, AsymmetricSecurityKey>> GetKeysAsync(IssuerConfiguration issuer, bool forceReload = false);
    }
}