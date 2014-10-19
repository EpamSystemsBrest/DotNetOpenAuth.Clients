using System;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class FlickrOAuthClient : IAuthenticationClient {
        private const string FlickrUrl = "https://www.flickr.com/";
        private const string SignatureMethod = "HMAC-SHA1";

        private readonly string _appId;
        private readonly string _appSecret;
        private string _tokenSecret;
        private static SignatureGenerator _signatureGenerator;

        public FlickrOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Flickr"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var requestTokenUrl = CreateRequestTokenUrl(returnUrl);
            var response = OAuthHelpers.Load(requestTokenUrl);
            RegenerateSignatureKey(response);

            var url = OAuthHelpers.BuildUri(FlickrUrl, "services/oauth/authorize", new NameValueCollection {
                {"oauth_token", HttpUtility.ParseQueryString(response).Get("oauth_token")}
            });

            context.Response.Redirect(url, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var url = CreateUserInfoUrl(context);
            var request = OAuthHelpers.Load(url);
            var userData = CreateUserInfo(request);
            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userData);
        }

        #endregion IAuthenticationClient

        private string CreateRequestTokenUrl(Uri returnUrl) {
            var parameters = new NameValueCollection
            {
                {"oauth_callback", SignatureGenerator.Encode(returnUrl.AbsoluteUri)},
                {"oauth_consumer_key", _appId},
                {"oauth_nonce", SignatureGenerator.GenerateNonce()},
                {"oauth_signature_method", SignatureMethod},
                {"oauth_timestamp", SignatureGenerator.GetTimestamp()},
                {"oauth_version", "1.0"},
            };
            var parametersString = OAuthHelpers.ConstructQueryString(parameters);

            var signature = _signatureGenerator.GenerateSignature("GET", FlickrUrl + "services/oauth/request_token", parametersString, true);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(FlickrUrl, "services/oauth/request_token", parameters);
        }

        private void RegenerateSignatureKey(string response) {
            _tokenSecret = HttpUtility.ParseQueryString(response).Get("oauth_token_secret");
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);
        }

        private string CreateUserInfoUrl(HttpContextBase context) {
            var parameters = new NameValueCollection
            {
                {"oauth_consumer_key", _appId},
                {"oauth_nonce", SignatureGenerator.GenerateNonce()},
                {"oauth_signature_method", "HMAC-SHA1"},
                {"oauth_timestamp", SignatureGenerator.GetTimestamp()},
                {"oauth_token", context.Request.QueryString["oauth_token"]},
                {"oauth_verifier", context.Request.QueryString["oauth_verifier"]},
                {"oauth_version", "1.0"},
            };
            var parametersString = OAuthHelpers.ConstructQueryString(parameters);

            var signature = _signatureGenerator.GenerateSignature("GET", FlickrUrl + "services/oauth/access_token", parametersString);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(FlickrUrl, "services/oauth/access_token", parameters);
        }

        public static UserInfo CreateUserInfo(string queryString) {
            var queryCollection = HttpUtility.ParseQueryString(queryString);

            return new UserInfo {
                Id = queryCollection.Get("user_nsid"),
                UserName = queryCollection.Get("fullname")
            };
        }
    }
}
