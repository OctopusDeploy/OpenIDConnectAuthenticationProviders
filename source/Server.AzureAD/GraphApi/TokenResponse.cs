using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Octopus.Server.Extensibility.Authentication.AzureAD.GraphApi
{
    internal class TokenResponse
    {
        [JsonProperty("token_type")]
        public string TokenType { get; set; } = string.Empty;
        [JsonProperty("scope")]
        public string Scope { get; set; } = string.Empty;
        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonProperty("ext_expires_in")]
        public int ExtExpiresIn { get; set; }
        [JsonProperty("access_token")]
        public string AccessToken { get; set; } = string.Empty;
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
