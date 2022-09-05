namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public class LoginRedirectLinkResponseModel
    {
        /// <summary>
        /// The Url to the portal should redirect to in order to initiate a login with this external authentication provider.
        /// </summary>
        public string ExternalAuthenticationUrl { get; set; } = string.Empty;
    }
}