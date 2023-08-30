using System;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigurationMap : IConfigurationDocumentMap
    {
        public Type GetTypeToMap() => typeof(AzureADConfiguration);
    }
}
