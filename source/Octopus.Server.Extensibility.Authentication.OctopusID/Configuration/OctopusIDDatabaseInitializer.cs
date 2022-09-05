using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;

namespace Octopus.Server.Extensibility.Authentication.OctopusID.Configuration
{
    class OctopusIDDatabaseInitializer : DatabaseInitializer<OctopusIDConfiguration>
    {
        readonly IConfigurationStore configurationStore;

        public OctopusIDDatabaseInitializer(IConfigurationStore configurationStore) : base(configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        protected override string SingletonId => OctopusIDConfigurationStore.SingletonId;

        public override void Execute()
        {
            base.Execute();
            
            var doc = configurationStore.Get<OctopusIDConfiguration>(SingletonId);

            if (doc.ConfigurationSchemaVersion == "1.0")
            {
                // the plugin was initially intended for hosted only, and was going to be always enabled. When
                // the distribution changed to include in all instances the default wasn't changed back to false.
                // This is a once off change to disable the provider in any existing instances that haven't been
                // configured by the cloud infrastructure to have to use Octopus ID
                doc.IsEnabled = !string.IsNullOrWhiteSpace(doc.ClientId);
                doc.ConfigurationSchemaVersion = "1.1";
                
                configurationStore.Update(doc);
            }
        }
    }
}