using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.Okta.Configuration
{
    class OktaDatabaseInitializer : DatabaseInitializer<OktaConfiguration>
    {
        public OktaDatabaseInitializer(IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        protected override string SingletonId => OktaConfigurationStore.SingletonId;
    }
}