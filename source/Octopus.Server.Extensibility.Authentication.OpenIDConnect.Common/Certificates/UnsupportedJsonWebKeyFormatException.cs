using System;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates
{
    public class UnsupportedJsonWebKeyFormatException : Exception
    {
        public UnsupportedJsonWebKeyFormatException(string message) : base(message)
        {
        }
    }
}