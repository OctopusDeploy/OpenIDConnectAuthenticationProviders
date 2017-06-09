﻿namespace Octopus.Node.Extensibility.Authentication.OpenIDConnect.Certificates
{
    public class RsaDetails : KeyDetails
    {
        public string Modulus { get; set; }
        public string Exponent { get; set; }
    }
}