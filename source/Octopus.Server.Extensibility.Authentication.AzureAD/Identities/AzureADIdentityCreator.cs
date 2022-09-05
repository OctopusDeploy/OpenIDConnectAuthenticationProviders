using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.Identities
{
    class AzureADIdentityCreator : IdentityCreator, IAzureADIdentityCreator
    {
        protected override string ProviderName => AzureADAuthenticationProvider.ProviderName;
    }

    interface IAzureADIdentityCreator : IIdentityCreator
    { }
}