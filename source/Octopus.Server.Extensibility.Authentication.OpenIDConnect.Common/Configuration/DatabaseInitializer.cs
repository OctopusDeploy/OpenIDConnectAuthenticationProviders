using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Extensions.Infrastructure;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration
{
    public abstract class DatabaseInitializer<TConfiguration> : ExecuteWhenDatabaseInitializes
        where TConfiguration : OpenIDConnectConfiguration, new()
    {
        readonly IConfigurationStore configurationStore;

        protected DatabaseInitializer(IConfigurationStore configurationStore)
        {
            this.configurationStore = configurationStore;
        }

        protected abstract string SingletonId { get; }

        public override void Execute()
        {
            var doc = configurationStore.Get<TConfiguration>(SingletonId);
            if (doc != null)
                return;

            configurationStore.Create(new TConfiguration());
        }
    }
}