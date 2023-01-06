﻿using System.Threading.Tasks;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer
{
    public interface IIdentityProviderConfigDiscoverer
    {
        Task<IssuerConfiguration> GetConfiguration(string issuer);
    }
}