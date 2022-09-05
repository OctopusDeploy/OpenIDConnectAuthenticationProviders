using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Issuer
{
    class GoogleKeyRetriever : KeyRetriever<IGoogleAppsConfigurationStore, IKeyJsonParser>, IGoogleKeyRetriever
    {
        public GoogleKeyRetriever(ISystemLog log, IGoogleAppsConfigurationStore configurationStore, IKeyJsonParser keyParser) : base(log, configurationStore, keyParser)
        {
        }
    }
}