using System;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    class OctopusIDConfigurationMapping : IConfigurationDocumentMapper
    {
        public Type GetTypeToMap() => typeof(OctopusIDConfiguration);
    }
}