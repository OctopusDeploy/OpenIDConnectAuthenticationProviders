using System;
using System.Security.Cryptography;
using System.Text;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class CodeChallenge
    {
        public static string CreateS256CodeChallenge(string codeVerifier)
        {
            using var sha = SHA256.Create();
            var codeChallenge = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier)))
                .TrimEnd('=').Replace("/", string.Empty).Replace("+", string.Empty);
            return codeChallenge;
        }
    }
}