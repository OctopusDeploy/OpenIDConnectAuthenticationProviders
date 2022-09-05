using System;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class AzureADConfigurationMapping : IConfigurationDocumentMapper
    {
        public Type GetTypeToMap() => typeof(AzureADConfiguration);
    }
}