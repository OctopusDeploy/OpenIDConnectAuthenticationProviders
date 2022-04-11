using System;
using System.Globalization;
using System.Linq;
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
using Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Tokens;
using Octopus.Server.Extensibility.Authentication.Resources;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Api;
using Octopus.Server.Extensibility.HostServices.Web;
using Octopus.Time;

namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Web
{
    public abstract class UserAuthenticatedAction<TStore, TAuthTokenHandler, TIdentityCreator> : IAsyncApiAction
        where TStore : IOpenIDConnectConfigurationStore
        where TAuthTokenHandler : IAuthTokenHandler
        where TIdentityCreator : IIdentityCreator
    {
        readonly ISystemLog log;
        readonly TAuthTokenHandler authTokenHandler;
        readonly IPrincipalToUserResourceMapper principalToUserResourceMapper;
        readonly TStore configurationStore;
        readonly IAuthCookieCreator authCookieCreator;
        readonly IInvalidLoginTracker loginTracker;
        readonly ISleep sleep;
        readonly TIdentityCreator identityCreator;
        readonly IUrlEncoder encoder;
        readonly IUserService userService;

        protected UserAuthenticatedAction(
            ISystemLog log,
            TAuthTokenHandler authTokenHandler,
            IPrincipalToUserResourceMapper principalToUserResourceMapper,
            TStore configurationStore,
            IAuthCookieCreator authCookieCreator,
            IInvalidLoginTracker loginTracker,
            ISleep sleep,
            TIdentityCreator identityCreator,
            IUrlEncoder encoder,
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
            this.userService = userService;
        }

        protected abstract string ProviderName { get; }

        public async Task<IOctoResponseProvider> ExecuteAsync(IOctoRequest request)
        {
            try
            {
                // Step 1: Try and get all of the details from the request making sure there are no errors passed back from the external identity provider
                var principalContainer = await authTokenHandler.GetPrincipalAsync(request.Form.ToDictionary(pair => pair.Key, pair => (string?)pair.Value), out var stateStringFromRequest);
                var principal = principalContainer.Principal;
                UserAuthenticatedValidator.ValidatePrincipalContainer(principal, principalContainer);

                // Step 2: Validate the state object we passed wasn't tampered with
                var expectedStateHash = string.Empty;
                if (request.Cookies.ContainsKey(UserAuthConstants.OctopusStateCookieName))
                    expectedStateHash = encoder.UrlDecode(request.Cookies[UserAuthConstants.OctopusStateCookieName]);
                UserAuthenticatedValidator.ValidateExpectedStateHashIsNotEmpty(expectedStateHash);

                var stateFromRequestHash = State.Protect(stateStringFromRequest);
                UserAuthenticatedValidator.ValidateReceivedStateIsEqualToExpectedState(stateFromRequestHash, expectedStateHash, stateStringFromRequest);

                var stateFromRequest = JsonConvert.DeserializeObject<LoginState>(stateStringFromRequest ?? string.Empty)!;

                // Step 3: Validate the nonce is as we expected to prevent replay attacks
                var expectedNonceHash = string.Empty;
                if (request.Cookies.ContainsKey(UserAuthConstants.OctopusNonceCookieName))
                    expectedNonceHash = encoder.UrlDecode(request.Cookies[UserAuthConstants.OctopusNonceCookieName]);

                UserAuthenticatedValidator.ValidateExpectedNonceHashIsNotEmpty(expectedNonceHash);

                var nonceFromClaims = principal!.Claims.FirstOrDefault(c => c.Type == "nonce");
                UserAuthenticatedValidator.ValidateNonceFromClaimsIsNotEmpty(nonceFromClaims);

                var nonceFromClaimsHash = Nonce.Protect(nonceFromClaims!.Value);
                UserAuthenticatedValidator.ValidateNonceFromClaimsHashIsEqualToExpectedNonce(expectedNonceHash, nonceFromClaimsHash, nonceFromClaims);

                // Step 4: Now the integrity of the request has been validated we can figure out which Octopus User this represents
                var authenticationCandidate = principalToUserResourceMapper.MapToUserResource(principal);
                UserAuthenticatedValidator.ValidateUsername(authenticationCandidate.Username);

                // Step 4a: Check if this authentication attempt is already being banned
                var action = loginTracker.BeforeAttempt(authenticationCandidate.Username, request.Host);
                UserAuthenticatedValidator.ValidateUserIsNotBanned(action);

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
                // Step 4b: Try to get or create a the Octopus User this external identity represents
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

                // Step 5: Handle other types of failures
                loginTracker.RecordFailure(authenticationCandidate.Username, request.Host);

                // Step 5a: Slow this potential attacker down a bit since they seem to keep failing
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
    }
}
