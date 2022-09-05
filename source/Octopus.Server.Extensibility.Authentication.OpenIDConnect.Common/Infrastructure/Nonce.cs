using System;
using System.Security.Cryptography;
using System.Text;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure
{
    public static class Nonce
    {
        static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        public static string GenerateUrlSafeNonce()
        {
            var data = new byte[16];
            // the reason to use 'GetNonZeroBytes' was to avoid x00 which may be interpretted as
            // https://crypto.stackexchange.com/questions/3396/why-x00-is-usually-avoided-in-salt
            // but it's not implemented in netcore
            // the claim is it shouldn't matter - http://stackoverflow.com/a/12704610/75963
            Rng.GetBytes(data);
            var nonce = Convert.ToBase64String(data).TrimEnd('=').Replace("/", string.Empty).Replace("+", string.Empty);
            return nonce;
        }

        public static string Protect(string nonce)
        {
            using (var sha = SHA256.Create())
            {
                var nonceHash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes("OctoNonce" + nonce)));
                return nonceHash;
            }
        }
    }
}