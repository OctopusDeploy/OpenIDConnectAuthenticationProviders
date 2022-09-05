using System;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Configuration
{
    class GoogleAppsConfigurationMapping : IConfigurationDocumentMapper
    {
        public Type GetTypeToMap() => typeof(GoogleAppsConfiguration);
    }
}