using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Infrastructure
{
    class OctopusIDPrincipalToUserResourceMapper : PrincipalToUserResourceMapper, IOctopusIDPrincipalToUserResourceMapper
    {
        readonly IOctopusIDConfigurationStore configurationStore;

        public OctopusIDPrincipalToUserResourceMapper(IOctopusIDConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }
    }
}