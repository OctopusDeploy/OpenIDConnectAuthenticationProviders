using System;
using System.Security.Cryptography;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class CodeVerifier
    {
        public static string? InMemoryCodeVerifier { get; private set; }
        static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        public static string GenerateUrlSafeCodeVerifier()
        {
            var data = new byte[32];
            Rng.GetBytes(data);
            var codeVerifier = Convert.ToBase64String(data).TrimEnd('=').Replace("/", string.Empty).Replace("+", string.Empty);
            InMemoryCodeVerifier = codeVerifier;
            return codeVerifier;
        }
    }
}