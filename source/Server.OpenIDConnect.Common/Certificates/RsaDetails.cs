namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates
{
    public class RsaDetails : KeyDetails
    {
        public string Modulus { get; set; } = string.Empty;
        public string Exponent { get; set; } = string.Empty;
    }
}