using System;
using System.Threading;
using System.Threading.Tasks;
using Octopus.Core.Infrastructure.Mapping;
using Octopus.Data.Model;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    class MapFromAzureADConfigurationResourceToAzureADConfiguration : IMapToNew<AzureADConfigurationResource, AzureADConfiguration>, IMapToExisting<AzureADConfigurationResource, AzureADConfiguration>
    {
        public async Task<AzureADConfiguration> Map(AzureADConfigurationResource source, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            var target = new AzureADConfiguration();

            target.IsEnabled = source.IsEnabled;
            target.Issuer = source.Issuer;
            target.RoleClaimType = source.RoleClaimType;
            target.AllowAutoUserCreation = source.AllowAutoUserCreation ?? false;
            target.ClientId = source.ClientId;

            if (source.ClientSecret is { HasValue: true, NewValue: { } })
            {
                target.ClientSecret = source.ClientSecret.NewValue.ToSensitiveString();
            }

            if (source.ClientSecret is not { HasValue: true })
            {
                target.ClientSecret = null;
            }

            if (source.ClientKey is { HasValue: true, NewValue: { } })
            {
                target.ClientKey = source.ClientKey.NewValue.ToSensitiveString();
            }

            if (source.ClientKey is not { HasValue: true })
            {
                target.ClientKey = null;
            }

            return target;
        }

        public async Task Map(AzureADConfigurationResource source, AzureADConfiguration target, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            target.IsEnabled = source.IsEnabled;
            target.Issuer = source.Issuer;
            target.RoleClaimType = source.RoleClaimType;
            target.AllowAutoUserCreation = source.AllowAutoUserCreation ?? false;
            target.ClientId = source.ClientId;

            if (source.ClientSecret is { HasValue: true, NewValue: { } })
            {
                target.ClientSecret = source.ClientSecret.NewValue.ToSensitiveString();
            }

            if (source.ClientSecret is not { HasValue: true })
            {
                target.ClientSecret = null;
            }
            
            if (source.ClientKey is { HasValue: true, NewValue: { } })
            {
                target.ClientKey = source.ClientKey.NewValue.ToSensitiveString();
            }

            if (source.ClientKey is not { HasValue: true })
            {
                target.ClientKey = null;
            }
        }
    }
}
