﻿using System;
using System.Security.Cryptography;
using System.Text;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Infrastructure
{
    public static class State
    {
        public static string Generate(string postLoginRedirectTo)
        {
            var state = "~/app";
            if (!string.IsNullOrWhiteSpace(postLoginRedirectTo))
                state = postLoginRedirectTo;
            return state;
        }

        public static string Protect(string state)
        {
            using (var sha = SHA256.Create())
            {
                var stateHash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes("OctoState" + state)));
                return stateHash;
            }
        }
    }
}