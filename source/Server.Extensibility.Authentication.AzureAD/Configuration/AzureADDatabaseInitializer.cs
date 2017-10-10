﻿using Octopus.Data.Storage.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Configuration;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    public class AzureADDatabaseInitializer : DatabaseInitializer<AzureADConfiguration>
    {
        public AzureADDatabaseInitializer(IConfigurationStore configurationStore) : base(configurationStore)
        {
        }

        protected override string SingletonId => AzureADConfigurationStore.SingletonId;
    }
}