using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using JWT;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using NUnit.Framework;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Tests.Helpers;

namespace Tests.OpenIdConnect.Tokens
{
    public class OpenIDFixtureBase
    {
        protected const string DefaultIssuer = "https://somedomain.com/";
        protected const string DefaultClientId = "Octopus Deploy";
        protected const string DefaultSubject = "12345";
        protected const string DefaultName = "bob";
        protected const string DefaultEmail = "bob@somedomain.com";

        protected const string KeyId = "88a8e79fba13856b4159f96e9c9ea6d5";
        protected const string Nonce = "";

        protected const string DefaultRedirect = "/infrastructure/machines/machines-1";

        class OctoRequest : IOctoRequest
        {
            public OctoRequest(string scheme, bool isHttps, string host, string pathBase, string path, string protocol, IDictionary<string, IEnumerable<string>> headers, IDictionary<string, string> form, IDictionary<string, string> cookies, IPrincipal user)
            {
                Scheme = scheme;
                IsHttps = isHttps;
                Host = host;
                PathBase = pathBase;
                Path = path;
                Protocol = protocol;
                Headers = headers;
                Form = form;
                Cookies = cookies;
                User = user;
            }

            public string Scheme { get; }
            public bool IsHttps { get; }
            public string Host { get; }
            public string PathBase { get; }
            public string Path { get; }
            public string Protocol { get; }
            public IDictionary<string, IEnumerable<string>> Headers { get; }
            public IDictionary<string, string> Form { get; }
            public IDictionary<string, string> Cookies { get; }
            public IPrincipal User { get; }

            public Task<IOctoResponseProvider> HandleAsync(Func<Task<IOctoResponseProvider>> onSuccess)
            {
                throw new NotImplementedException();
            }

            public Task<IOctoResponseProvider> HandleAsync<T>(IResponderParameter<T> parameter, Func<T, Task<IOctoResponseProvider>> onSuccess)
            {
                throw new NotImplementedException();
            }

            public Task<IOctoResponseProvider> HandleAsync<T1, T2>(IResponderParameter<T1> parameter1, IResponderParameter<T2> parameter2, Func<T1, T2, Task<IOctoResponseProvider>> onSuccess)
            {
                throw new NotImplementedException();
            }

            public Task<IOctoResponseProvider> HandleAsync<T1, T2, T3>(IResponderParameter<T1> parameter1, IResponderParameter<T2> parameter2, IResponderParameter<T3> parameter3, Func<T1, T2, T3, Task<IOctoResponseProvider>> onSuccess)
            {
                throw new NotImplementedException();
            }

            public Task<IOctoResponseProvider> HandleAsync<T1, T2, T3, T4>(IResponderParameter<T1> parameter1, IResponderParameter<T2> parameter2, IResponderParameter<T3> parameter3, IResponderParameter<T4> parameter4, Func<T1, T2, T3, T4, Task<IOctoResponseProvider>> onSuccess)
            {
                throw new NotImplementedException();
            }

            public Task<IOctoResponseProvider> HandleAsync<T1, T2, T3, T4, T5>(IResponderParameter<T1> parameter1, IResponderParameter<T2> parameter2, IResponderParameter<T3> parameter3, IResponderParameter<T4> parameter4, IResponderParameter<T5> parameter5, Func<T1, T2, T3, T4, T5, Task<IOctoResponseProvider>> onSuccess)
            {
                throw new NotImplementedException();
            }

            public TResource GetBody<TResource>(RequestBodyRegistration<TResource> registration)
            {
                throw new NotImplementedException();
            }
        }

        protected IOctoRequest CreateRequest(string token, string redirectAfterLoginTo = DefaultRedirect, bool usingSecureConnection = false)
        {
            var request = new OctoRequest("https", true, DefaultIssuer, String.Empty, string.Empty, "http", null, new Dictionary<string, string>(), null, null);
            //request.Form["access_token"] = null;
            request.Form["id_token"] = token;
            var stateData = JsonConvert.SerializeObject(new LoginState {RedirectAfterLoginTo = redirectAfterLoginTo, UsingSecureConnection = usingSecureConnection});
            request.Form["state"] = stateData;
            return request;
        }

        protected string CreateToken(
            string keyId,
            out RsaSecurityKey key,
            string issuer = DefaultIssuer,
            string clientId = DefaultClientId,
            string nonce = Nonce,
            string subject = DefaultSubject,
            string name = DefaultName,
            string email = DefaultEmail,
            string[] roleIds = null,
            string[] groupIds = null)
        {
            var epoch = new DateTime(1970, 1, 1);
            var now = Math.Round((DateTime.Now - epoch).TotalSeconds);
            var exp = now + 36000;

            var payload = new Dictionary<string, object>
            {
                { "aud", clientId },
                { "iss", issuer },
                { "exp", exp },
                { "iat", now },
                { "nonce", nonce },
                { "sub", subject},
                { "name", name},
                { "email", email}
            };

            var headers = new Dictionary<string, object>
            {
                { "kid",  keyId}
            };

            if (roleIds != null && roleIds.Any())
            {
                payload.Add("roles", roleIds);
            }
            if (groupIds != null && groupIds.Any())
            {
                payload.Add("groups", groupIds);
            }

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var rsaParametersPublic = rsa.ExportParameters(includePrivateParameters: false);
                key = new RsaSecurityKey(rsaParametersPublic) {KeyId = keyId};

                var algorithm = new RS256AlgorithmRsaOnly(rsa);
                var serializer = new JsonNetSerializer();
                var urlEncoder = new JwtBase64UrlEncoder();
                var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
                var token = encoder.Encode(headers, payload, string.Empty);

                return token;
            }
        }

        protected void AssertClaims(
            ClaimsPrincipal principal,
            string issuer = DefaultIssuer,
            string clientid = DefaultClientId,
            string nonce = Nonce,
            string subject = DefaultSubject,
            string name = DefaultName,
            string email = DefaultEmail)
        {
            Assert.IsTrue(principal.HasClaim(x => x.Type == "iss" && x.Value == issuer));
            Assert.IsTrue(principal.HasClaim(x => x.Type == "aud" && x.Value == clientid));
            Assert.IsTrue(principal.HasClaim(x => x.Type == "nonce" && x.Value == nonce));
            Assert.IsTrue(principal.HasClaim(x => x.Type == "name" && x.Value == name));
            Assert.IsTrue(principal.HasClaim(x => x.Type == ClaimTypes.NameIdentifier && x.Value == subject));
            Assert.IsTrue(principal.HasClaim(x => x.Type == ClaimTypes.Email && x.Value == email));
        }
    }
}