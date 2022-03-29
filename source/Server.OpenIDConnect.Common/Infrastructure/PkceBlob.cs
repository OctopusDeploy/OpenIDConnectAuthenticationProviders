using System;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public class PkceBlob
    {
        public Guid SessionId { get; }
        public string CodeVerifier { get; }
        public DateTimeOffset TimeStamp { get; }

        public PkceBlob(Guid sessionId, string codeVerifier, DateTimeOffset timeStamp)
        {
            SessionId = sessionId;
            CodeVerifier = codeVerifier;
            TimeStamp = timeStamp;
        }
    }
}