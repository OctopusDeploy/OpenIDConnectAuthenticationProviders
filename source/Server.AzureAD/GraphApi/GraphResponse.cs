using Newtonsoft.Json;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.GraphApi
{
    internal class GraphResponse
    {
        [JsonProperty("@odata.context")]
        public string? Context { get; set; }
        [JsonProperty("@odata.nextLink")]
        public string? NextLink { get; set; }
        [JsonProperty("value")]
        public MembershipEntity[]? Value { get; set; }
    }
}
