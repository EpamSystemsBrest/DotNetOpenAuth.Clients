using System.Collections.Specialized;
using DotNetOpenAuth.AspNet;
using System;
using System.Web;

namespace DotNetOpenAuth.Clients {
    public class TwitterOAuthClient : IAuthenticationClient {
        private const string SignatureMethod = "HMAC-SHA1";
        private const string OAuthUrl = "https://api.twitter.com/";
        private const string OAuthAuthenticatePath = "oauth/authenticate";
        private const string OAuthRequestTokenPath = "oauth/request_token";
        private const string OAuthAccessTokenPath = "oauth/access_token";
        private const string OAuthValue = "1.0";

        private readonly string _appId;
        private readonly string _appSecret;
        private string _redirectUri;
        private string _tokenSecret;
        private static SignatureGenerator _signatureGenerator;

        public TwitterOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Twitter"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            _redirectUri = returnUrl.AbsoluteUri;

            var url = CreateRequestTokenUrl();
            var request = OAuthHelpers.Load(url);
            var requestToken = OAuthHelpers.GetValueFromRequest(request, "oauth_token");
            _tokenSecret = OAuthHelpers.GetValueFromRequest(request, "oauth_token_secret");
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);

            var redirectUrl = CreateRedirectUrl(requestToken);
            context.Response.Redirect(redirectUrl, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var url = CreateUserInfoUrl(context);
            var response = OAuthHelpers.Load(url);
            var queryCollection = HttpUtility.ParseQueryString(response);

            var userInfo = new UserInfo {
                Id = queryCollection.Get("user_id"),
                UserName = queryCollection.Get("screen_name")
            };

            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userInfo);
        }

        #endregion

        private string CreateRequestTokenUrl() {
            var parameters = new NameValueCollection {
                { "oauth_callback",         SignatureGenerator.Encode(_redirectUri) },
                { "oauth_consumer_key",     _appId },
                { "oauth_nonce",            SignatureGenerator.GenerateNonce() },
                { "oauth_signature_method", SignatureMethod },
                { "oauth_timestamp",        SignatureGenerator.GetTimestamp() },
                { "oauth_version",          OAuthValue }
            };

            var parametersString = OAuthHelpers.ConstructQueryString(parameters);
            var signature = _signatureGenerator.GenerateSignature("GET", OAuthUrl + OAuthRequestTokenPath, parametersString, true);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(OAuthUrl, OAuthRequestTokenPath, parameters);
        }

        private static string CreateRedirectUrl(string requestToken) {
            var parameters = new NameValueCollection {
                { "oauth_token", requestToken }
            };
            return OAuthHelpers.BuildUri(OAuthUrl, OAuthAuthenticatePath, parameters);
        }

        private string CreateUserInfoUrl(HttpContextBase context) {
            var parameters = new NameValueCollection {
                { "oauth_consumer_key",         _appId },
                { "oauth_nonce",                SignatureGenerator.GenerateNonce() },
                { "oauth_signature_method",     SignatureMethod },
                { "oauth_timestamp",            SignatureGenerator.GetTimestamp() },
                { "oauth_token",                context.Request.QueryString["oauth_token"] },
                { "oauth_verifier",             context.Request.QueryString["oauth_verifier"] },
                { "oauth_version",              OAuthValue }
            };

            var parametersString = OAuthHelpers.ConstructQueryString(parameters);
            var signature = _signatureGenerator.GenerateSignature("GET", OAuthUrl + OAuthAccessTokenPath, parametersString);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(OAuthUrl, OAuthAccessTokenPath, parameters);
        }
    }
}
