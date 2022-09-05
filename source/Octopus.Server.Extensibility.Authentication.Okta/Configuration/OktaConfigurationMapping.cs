using System;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    class OktaConfigurationMapping : IConfigurationDocumentMapper
    {
        public Type GetTypeToMap() => typeof(OktaConfiguration);
    }
}