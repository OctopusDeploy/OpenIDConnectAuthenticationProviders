using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Octopus.Data;
using Octopus.Data.Model.User;
using Octopus.Diagnostics;
using Octopus.Server.Extensibility.Authentication.HostServices;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Configuration;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Identities;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Infrastructure;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Issuer;
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Server.Extensibility.Mediator;
using Octopus.Server.MessageContracts.Features.BlobStorage;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticatedPkceAction<TStore, TAuthTokenHandler, TIdentityCreator> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthTokenHandler : IAuthTokenHandler
        where TIdentityCreator : IIdentityCreator
    {
        readonly RequiredQueryParameterProperty<string> codeParameter = new("code", "Authorization code provided by the identity provider");
        readonly OptionalQueryParameterProperty<string> stateParameter = new("state", "The state value associated with the authentication session");

        readonly ISystemLog log;
        readonly TAuthTokenHandler authTokenHandler;
        readonly IPrincipalToUserResourceMapper principalToUserResourceMapper;
        readonly TStore configurationStore;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly TIdentityCreator identityCreator;
        readonly IUrlEncoder encoder;
        readonly IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer;
        readonly IMediator mediator;
        readonly IUserService userService;

        protected UserAuthenticatedPkceAction(ISystemLog log,
            TAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            TStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            TIdentityCreator identityCreator,
            IUrlEncoder encoder,
            IIdentityProviderConfigDiscoverer identityProviderConfigDiscoverer,
            IMediator mediator,
            IUserService userService)
        {
            this.log = log;
            this.authTokenHandler = authTokenHandler;
            this.principalToUserResourceMapper = principalToUserResourceMapper;
            this.configurationStore = configurationStore;
            this.authCookieCreator = authCookieCreator;
            this.loginTracker = loginTracker;
            this.sleep = sleep;
            this.identityCreator = identityCreator;
            this.encoder = encoder;
            this.identityProviderConfigDiscoverer = identityProviderConfigDiscoverer;
            this.mediator = mediator;
            this.userService = userService;
        }

        protected abstract string ProviderName { get; }

        public async Task<IOctoResponseProvider> ExecuteAsync(IOctoRequest request)
        {
            return await request.HandleAsync(codeParameter, stateParameter, (code, state) => Handle(code, state, request));
        }

        async Task<IOctoResponseProvider> Handle(string code, string state, IOctoRequest request)
        {
            var stateFromRequest = JsonConvert.DeserializeObject<LoginStateWithRequestId>(state)!;

            var blobs = await GetAllPkceBlobsBelongingToExtension();
            var blobFromOriginalRequest = blobs.Single(b => b.RequestId == stateFromRequest.RequestId);
            await RemoveBlob(blobFromOriginalRequest);
            await RemoveExpiredBlobs(blobs);

            var host = request.Headers.ContainsKey("Host") ? request.Headers["Host"].Single() : request.Host;
            var redirectUri = $"{request.Scheme}://{host}{configurationStore.RedirectUri}";
            var response = await RequestAuthToken(code, redirectUri, blobFromOriginalRequest.CodeVerifier);

            try
            {
                // Step 1: Try and get all of the details from the request making sure there are no errors passed back from the external identity provider
                var principalContainer = await authTokenHandler.GetPrincipalAsync(response, out var stateStringFromRequest);
                var principal = principalContainer.Principal;
                UserAuthenticatedValidator.ValidatePrincipalContainer(principal, principalContainer);

                // Step 2: Validate the state object we passed wasn't tampered with
                var expectedStateHash = string.Empty;
                stateStringFromRequest ??= state;
                if (request.Cookies.ContainsKey(UserAuthConstants.OctopusStateCookieName))
                    expectedStateHash = encoder.UrlDecode(request.Cookies[UserAuthConstants.OctopusStateCookieName]);
                UserAuthenticatedValidator.ValidateExpectedStateHashIsNotEmpty(expectedStateHash);

                var stateFromRequestHash = State.Protect(stateStringFromRequest);
                UserAuthenticatedValidator.ValidateReceivedStateIsEqualToExpectedState(stateFromRequestHash, expectedStateHash, stateStringFromRequest);

                // Step 3: Now the integrity of the request has been validated we can figure out which Octopus User this represents
                var authenticationCandidate = principalToUserResourceMapper.MapToUserResource(principal!);
                UserAuthenticatedValidator.ValidateUsername(authenticationCandidate.Username);

                // Step 3a: Check if this authentication attempt is already being banned
                var action = loginTracker.BeforeAttempt(authenticationCandidate.Username, request.Host);
                UserAuthenticatedValidator.ValidateUserIsNotBanned(action);

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
                // Step 3b: Try to get or create a the Octopus User this external identity represents
                var userResult = userService.GetOrCreateUser(authenticationCandidate, principalContainer.ExternalGroupIds, ProviderName, identityCreator, configurationStore.GetAllowAutoUserCreation(), cts.Token);
                if (userResult is ISuccessResult<IUser> successResult)
                {
                    loginTracker.RecordSucess(authenticationCandidate.Username, request.Host);

                    UserAuthenticatedValidator.ValidateUserIsActive(successResult.Value.IsActive, authenticationCandidate.Username);
                    UserAuthenticatedValidator.ValidateUserIsNotServiceAccount(successResult.Value.IsService, authenticationCandidate.Username);

                    var octoResponse = UserAuthenticatedValidator.Redirect.Response(stateFromRequest.RedirectAfterLoginTo)
                        .WithHeader("Expires", new[] {DateTime.UtcNow.AddYears(1).ToString("R", DateTimeFormatInfo.InvariantInfo)})
                        .WithCookie(new OctoCookie(UserAuthConstants.OctopusStateCookieName, Guid.NewGuid().ToString()) {HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue})
                        .WithCookie(new OctoCookie(UserAuthConstants.OctopusNonceCookieName, Guid.NewGuid().ToString()) {HttpOnly = true, Secure = false, Expires = DateTimeOffset.MinValue});

                    var authCookies = authCookieCreator.CreateAuthCookies(successResult.Value.IdentificationToken, TimeSpan.FromDays(20), request.IsHttps, stateFromRequest.UsingSecureConnection);

                    foreach (var cookie in authCookies)
                    {
                        octoResponse = octoResponse.WithCookie(cookie);
                    }

                    return octoResponse;
                }

                // Step 4: Handle other types of failures
                loginTracker.RecordFailure(authenticationCandidate.Username, request.Host);

                // Step 4a: Slow this potential attacker down a bit since they seem to keep failing
                if (action == InvalidLoginAction.Slow)
                {
                    sleep.For(1000);
                }

                throw new FailedAuthenticationException($"User login failed: {((IFailureResult) userResult).ErrorString}");
            }
            catch (FailedAuthenticationException e)
            {
                return UserAuthenticatedValidator.BadRequest(log, e.Message);
            }
        }

        async Task<IDictionary<string, string?>> RequestAuthToken(string code, string redirectUri, string codeVerifier)
        {
            var issuerConfig = await identityProviderConfigDiscoverer.GetConfigurationAsync(configurationStore.GetIssuer() ?? string.Empty);
            using var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, issuerConfig.TokenEndpoint);

            var formValues = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = configurationStore.GetClientId()!,
                ["client_secret"] = configurationStore.GetClientSecret()!.Value,
                ["code_verifier"] = codeVerifier
            };
            request.Content = new FormUrlEncodedContent(formValues!);
            var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            var body = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<Dictionary<string, string?>>(body)!;
        }

        async Task<List<PkceBlob>> GetAllPkceBlobsBelongingToExtension()
        {
            var allBlobsBelongingToExtension = await mediator.Request(new GetAllBlobsRequest(configurationStore.ConfigurationSettingsName), new CancellationToken());
            var pkceBlobs = new List<PkceBlob>();
            foreach (var blob in allBlobsBelongingToExtension.Blobs)
            {
                try
                {
                    pkceBlobs.Add(JsonConvert.DeserializeObject<PkceBlob>(Encoding.UTF8.GetString(blob))!);
                }
                catch (Exception e)
                {
                    log.Warn($"Could not parse blob. This is most likely not a PkceBlob and will be skipped: {e.Message}");
                }
            }
            return pkceBlobs;
        }

        async Task RemoveExpiredBlobs(IEnumerable<PkceBlob> blobs)
        {
            foreach (var blob in blobs.Where(blob => DateTimeOffset.UtcNow.Subtract(blob.TimeStamp).TotalSeconds > 30))
            {
                await RemoveBlob(blob);
            }
        }

        async Task RemoveBlob(PkceBlob blob)
        {
            await mediator.Do(new DeleteBlobCommand(configurationStore.ConfigurationSettingsName, blob.RequestId.ToString()), new CancellationToken());
        }
    }
}
