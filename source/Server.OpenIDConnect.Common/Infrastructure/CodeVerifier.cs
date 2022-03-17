using System;
using System.Security.Cryptography;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class CodeVerifier
    {
        public static string? InMemoryCodeVerifier { get; private set; }
        static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        public static string GenerateCodeVerifier(int size = 128)
        {
            if (size is < 43 or > 128)
                size = 128;

            const string unreservedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            Random random = new();
            char[] highEntropyCryptograph = new char[size];

            for (var i = 0; i < highEntropyCryptograph.Length; i++)
            {
                highEntropyCryptograph[i] = unreservedCharacters[random.Next(unreservedCharacters.Length)];
            }

            var codeVerifier = new string(highEntropyCryptograph);
            InMemoryCodeVerifier = codeVerifier;
            return codeVerifier;
        }
    }
}