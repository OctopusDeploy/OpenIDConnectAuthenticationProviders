using System;
using Octopus.Server.Extensibility.HostServices.Mapping;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Configuration
{
    static class AzureADConfigurationMapper
    {
        public static AzureADConfigurationResource MapToResource(AzureADConfiguration model) =>
            new()
            {
                Id = model.Id,
                IsEnabled = model.IsEnabled,
                AllowAutoUserCreation = model.AllowAutoUserCreation,
                Issuer = model.Issuer,
                ClientId = model.ClientId,
                ClientSecret = model.ClientSecret.ToSensitiveValue(),
                ClientKey = model.ClientKey.ToSensitiveValue(),
                RoleClaimType = model.RoleClaimType
            };

        public static void ModifyModel(AzureADConfigurationResource resource, AzureADConfiguration model)
        {
            model.IsEnabled = resource.IsEnabled;
            model.AllowAutoUserCreation = resource.AllowAutoUserCreation == true;
            model.Issuer = resource.Issuer;
            model.ClientId = resource.ClientId;
            model.ClientSecret = resource.ClientSecret.ToSensitiveStringOrExisting(model.ClientSecret);
            model.ClientKey = resource.ClientKey.ToSensitiveStringOrExisting(model.ClientKey);
            model.RoleClaimType = resource.RoleClaimType;
        }
    }
}
