using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class CodeChallenge
    {
        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha = SHA256.Create();
            var challengeBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncoder.Encode(challengeBytes);
        }
    }
}