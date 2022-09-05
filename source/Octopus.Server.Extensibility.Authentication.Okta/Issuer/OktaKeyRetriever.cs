using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.Okta.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Octopus.Server.Extensibility.Authentication.Okta.Issuer
{
    class OktaKeyRetriever : KeyRetriever<IOktaConfigurationStore, IKeyJsonParser>, IOktaKeyRetriever
    {
        public OktaKeyRetriever(ISystemLog log, IOktaConfigurationStore configurationStore, IKeyJsonParser keyParser) : base(log, configurationStore, keyParser)
        {
        }
    }
}