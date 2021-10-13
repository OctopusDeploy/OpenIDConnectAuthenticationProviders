using Newtonsoft.Json;
using System;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.GraphApi
{
    internal class MembershipEntity
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;
    }
}
