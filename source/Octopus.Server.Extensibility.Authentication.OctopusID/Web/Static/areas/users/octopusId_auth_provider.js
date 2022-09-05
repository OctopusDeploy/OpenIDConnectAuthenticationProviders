(function (providerName) {

function octopusIDAuthProvider(octopusClient, provider, loginState, onError) {

    this.linkHtml = '<a><div class="octopusID-button"><div><em class="fontoctopus-octopus" style="font-size:23px; margin-right:10px;"></em> Sign in with your Octopus ID</div></div></a>';

    this.signIn = function () {
        console.log("Signing in using " + providerName + " provider");

        var authUri = provider.Links.Authenticate;
        var redirectToLink = function (externalProviderLink) {
            window.location.href = externalProviderLink.ExternalAuthenticationUrl;
        };
        var postData = {
            ApiAbsUrl: octopusClient.resolve("~/"),
            State: loginState
        };

        octopusClient.post(authUri, postData)
                    .then(redirectToLink, onError);
    };

    return {
        Name: providerName,
        LinkHtml: this.linkHtml,
        SignIn: this.signIn
    };
}

console.log("Registering " + providerName + " auth provider");
window.Octopus.registerExtension(providerName, "auth_provider", octopusIDAuthProvider);

})("Octopus ID");
