using System.Security.Cryptography;
using JWT;
using JWT.Algorithms;

namespace Tests.Helpers
{
    public class RS256AlgorithmRsaOnly : IJwtAlgorithm
    {
        readonly RSACryptoServiceProvider rsa;
        public RS256AlgorithmRsaOnly(RSACryptoServiceProvider rsa)
        {
            this.rsa = rsa;
        }

        public string Name => JwtHashAlgorithm.RS256.ToString();
        public bool IsAsymmetric { get; }

        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            return rsa.SignData(bytesToSign, CryptoConfig.MapNameToOID("SHA256"));
        }
    }
}
