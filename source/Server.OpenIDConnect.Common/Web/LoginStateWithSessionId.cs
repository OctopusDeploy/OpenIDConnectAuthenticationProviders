using System;
using Octopus.Server.Extensibility.Authentication.Resources;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    class LoginStateWithSessionId : LoginState
    {
        public Guid SessionId { get; set; }

        public LoginStateWithSessionId(string redirectAfterLoginTo, bool usingSecureConnection, Guid sessionId)
        {
            RedirectAfterLoginTo = redirectAfterLoginTo;
            UsingSecureConnection = usingSecureConnection;
            SessionId = sessionId;
        }
    }
}