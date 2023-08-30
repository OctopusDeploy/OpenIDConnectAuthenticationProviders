using System;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Core.Infrastructure.Mapping;
using Octopus.Server.MessageContracts;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class MapFromAzureADConfigurationToAzureADConfigurationResource : IMapToNew<AzureADConfiguration, AzureADConfigurationResource>
    {
        public async Task<AzureADConfigurationResource> Map(AzureADConfiguration source, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            var target = new AzureADConfigurationResource();

            target.Id = source.Id;
            target.IsEnabled = source.IsEnabled;
            target.AllowAutoUserCreation = source.AllowAutoUserCreation;
            target.RoleClaimType = source.RoleClaimType;
            target.Issuer = source.Issuer;
            target.ClientId = source.ClientId;

            if (source.ClientSecret == null)
            {
                target.ClientSecret = null;
            }
            else
            {
                target.ClientSecret = !string.IsNullOrWhiteSpace(source.ClientSecret?.Value) ? new SensitiveValue { HasValue = true } : new SensitiveValue { HasValue = false };
            }

            if (source.ClientKey == null)
            {
                target.ClientKey = null;
            }
            else
            {
                target.ClientKey = !string.IsNullOrWhiteSpace(source.ClientKey?.Value) ? new SensitiveValue { HasValue = true } : new SensitiveValue { HasValue = false };
            }

            return target;
        }
    }
}
