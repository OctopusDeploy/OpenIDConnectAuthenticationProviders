using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class Pkce
    {
        const string UnreservedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        public static string? InMemoryCodeVerifier { get; private set; }

        public static string GenerateCodeVerifier(int size = 128)
        {
            if (size is < 43 or > 128)
                size = 128;

            Random random = new();
            char[] highEntropyCryptograph = new char[size];

            for (var i = 0; i < highEntropyCryptograph.Length; i++)
            {
                highEntropyCryptograph[i] = UnreservedCharacters[random.Next(UnreservedCharacters.Length)];
            }

            var codeVerifier = new string(highEntropyCryptograph);
            InMemoryCodeVerifier = codeVerifier;
            return codeVerifier;
        }

        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha = SHA256.Create();
            var challengeBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncoder.Encode(challengeBytes);
        }
    }
}