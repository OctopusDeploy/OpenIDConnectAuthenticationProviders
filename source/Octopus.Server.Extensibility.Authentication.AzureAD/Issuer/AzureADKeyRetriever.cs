using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.AzureAD.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Issuer
{
    class AzureADKeyRetriever : KeyRetriever<IAzureADConfigurationStore, IKeyJsonParser>, IAzureADKeyRetriever
    {
        public AzureADKeyRetriever(ISystemLog log, IAzureADConfigurationStore configurationStore, IKeyJsonParser keyParser) : base(log, configurationStore, keyParser)
        {
        }
    }
}