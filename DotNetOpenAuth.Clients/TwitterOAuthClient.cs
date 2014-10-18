using DotNetOpenAuth.AspNet;
using System;
using System.Web;

namespace DotNetOpenAuth.Clients {
    public class TwitterOAuthClient : IAuthenticationClient {
        private const string RequestTokenUrl = "https://api.twitter.com/oauth/request_token";
        private const string AccessTokenUrl = "https://api.twitter.com/oauth/access_token";
        private const string AuthorizeUrl = "https://api.twitter.com/oauth/authenticate";
        private const string SignatureMethod = "HMAC-SHA1";

        private readonly string _appId;
        private readonly string _appSecret;
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
            var url = CreateRequestTokenUrl(returnUrl);
            var request = OAuthHelpers.Load(url);
            var requestToken = OAuthHelpers.GetValueFromRequest(request, "oauth_token");
            _tokenSecret = OAuthHelpers.GetValueFromRequest(request, "oauth_token_secret");
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);

            HttpContext.Current.Response.Redirect(AuthorizeUrl + "?oauth_token=" + requestToken, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var url = CreateUserInfoUrl(context);

            var request = OAuthHelpers.Load(url);
            var queryCollection = HttpUtility.ParseQueryString(request);

            var userInfo = new UserInfo {
                Id = queryCollection.Get("user_id"),
                UserName = queryCollection.Get("screen_name")
            };

            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userInfo);
        }

        #endregion

        private string CreateUserInfoUrl(HttpContextBase context) {
            var oauthVerifier = context.Request.QueryString["oauth_verifier"];
            var oauthToken = context.Request.QueryString["oauth_token"];

            var parameters = "oauth_consumer_key=" + _appId +
                             "&oauth_nonce=" + SignatureGenerator.GenerateNonce() +
                             "&oauth_signature_method=HMAC-SHA1" +
                             "&oauth_timestamp=" + SignatureGenerator.GetTimestamp() +
                             "&oauth_token=" + oauthToken +
                             "&oauth_verifier=" + oauthVerifier +
                             "&oauth_version=1.0";

            var signature = _signatureGenerator.GenerateSignature("GET", AccessTokenUrl, parameters);
            return AccessTokenUrl + "?" + parameters + "&oauth_signature=" + signature;
        }

        private string CreateRequestTokenUrl(Uri returnUrl) {
            var parameters = "oauth_callback=" + SignatureGenerator.Encode(returnUrl.AbsoluteUri) +
                             "&oauth_consumer_key=" + _appId +
                             "&oauth_nonce=" + SignatureGenerator.GenerateNonce() +
                             "&oauth_signature_method=" + SignatureMethod +
                             "&oauth_timestamp=" + SignatureGenerator.GetTimestamp() +
                             "&oauth_version=1.0";

            var signature = _signatureGenerator.GenerateSignature("GET", RequestTokenUrl, parameters, true);

            return RequestTokenUrl + "?" + parameters + "&oauth_signature=" + signature;
        }
    }
}
