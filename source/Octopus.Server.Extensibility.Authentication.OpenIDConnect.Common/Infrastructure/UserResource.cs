namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public class UserResource
    {
        public string? Username { get; set; }
        public string? DisplayName { get; set; }
        public string? EmailAddress { get; set; }
        public string? ExternalId { get; set; }
    }
}