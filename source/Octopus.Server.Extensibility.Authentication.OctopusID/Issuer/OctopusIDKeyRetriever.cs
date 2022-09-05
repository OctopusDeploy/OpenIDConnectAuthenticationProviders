using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.OctopusID.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Issuer
{
    class OctopusIDKeyRetriever : KeyRetriever<IOctopusIDConfigurationStore, IKeyJsonParser>, IOctopusIDKeyRetriever
    {
        public OctopusIDKeyRetriever(ISystemLog log, IOctopusIDConfigurationStore configurationStore, IKeyJsonParser keyParser) : base(log, configurationStore, keyParser)
        {
        }
    }
}