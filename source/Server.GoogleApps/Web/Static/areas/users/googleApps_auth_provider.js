(function (providerName) {

function googleAuthProvider(octopusClient, provider, loginState, onError, isDarkMode) {
    this.linkHtml = `
        <a>
            <div class="googleapps-button ${isDarkMode ? "dark" : "light"}">
                <div class="googleapps-button-image">
                    <img alt="Login using Google Auth" src="${octopusClient.resolve("~/images/google_signin_buttons/icon-google.svg")}" />
                </div>
                <span class="googleapps-button-text">Sign in with Google</span>
            </div>
        </a>
    `;

    this.signIn = function () {

        console.log("Signing in using " + providerName + " provider");

        var authLink = provider.Links.Authenticate;
        var redirectToLink = function (externalProviderLink) {
            window.location.href = externalProviderLink.ExternalAuthenticationUrl;
        };
        var postData = {
            ApiAbsUrl: octopusClient.resolve("~/"),
            State: loginState
        };

        octopusClient.post(authLink, postData)
                    .then(redirectToLink, onError);
    };

    return {
        Name: providerName,
        LinkHtml: this.linkHtml,
        SignIn: this.signIn
    };
}

console.log("Registering " + providerName + " auth provider");
window.Octopus.registerExtension(providerName, "auth_provider", googleAuthProvider);

})("Google Apps");