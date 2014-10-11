using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients
{
    public class TumblrOAuthClient : IAuthenticationClient
    {
        private const string TumblrUrl = "https://www.tumblr.com/";
        private const string TumblrApi = "https://api.tumblr.com/";

        private const string SignatureMethod = "HMAC-SHA1";

        private readonly string _appId;
        private readonly string _appSecret;

        private string _tokenSecret;

        private static SignatureGenerator _signatureGenerator;

        public TumblrOAuthClient(string appId, string appSecret)
        {
            _appId = appId;
            _appSecret = appSecret;
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Tumblr"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var requestTokenUrl = CreateRequestTokenUrl(returnUrl);
            var response = OAuthHelpers.Load(requestTokenUrl);
            RegenerateSignatureKey(response);

            var url = OAuthHelpers.BuildUri(TumblrUrl, "oauth/authorize", new NameValueCollection
            {
                {"oauth_token", OAuthHelpers.GetValueFromRequest(response, "oauth_token" ) }
            });

            context.Response.Redirect(url, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            var url = CreateAccessTokenUrl(context);
            var response = OAuthHelpers.Load(url);
            RegenerateSignatureKey(response);
            var userData = GetUserData(OAuthHelpers.GetValueFromRequest(response, "oauth_token"));
         
            return CreateAuthenticationResult(userData);
        }

        #endregion IAuthenticationClient

        private string CreateRequestTokenUrl(Uri returnUrl)
        {
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

            var signature = _signatureGenerator.GenerateSignature("GET", TumblrUrl + "oauth/request_token", parametersString, true);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(TumblrUrl, "oauth/request_token", parameters);
        }

        private void RegenerateSignatureKey(string response)
        {
            _tokenSecret = HttpUtility.ParseQueryString(response).Get("oauth_token_secret");
            _signatureGenerator = new SignatureGenerator(_appSecret, _tokenSecret);
        }

        private string CreateAccessTokenUrl(HttpContextBase context)
        {
            var parameters = new NameValueCollection
            {
                {"oauth_consumer_key", _appId},
                {"oauth_nonce", SignatureGenerator.GenerateNonce()},
                {"oauth_signature_method", "HMAC-SHA1"},
                {"oauth_timestamp", SignatureGenerator.GetTimestamp()},
                {"oauth_token", context.Request["oauth_token"]},
                {"oauth_verifier", context.Request["oauth_verifier"]},
                {"oauth_version", "1.0"},
            };
            var parametersString = OAuthHelpers.ConstructQueryString(parameters);

            var signature = _signatureGenerator.GenerateSignature("GET", TumblrUrl + "oauth/access_token", parametersString);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(TumblrUrl, "oauth/access_token", parameters);
        }

        private UserData GetUserData(string token)
        {
            var url = CreateUserInfoUrl(token);

            // 401: Not Autorized 
            var response = OAuthHelpers.Load(url);

            return OAuthHelpers.DeserializeJson<UserData>(response);
        }

        private string CreateUserInfoUrl(string token)
        {
            var parameters = new NameValueCollection
            {
                {"oauth_consumer_key", _appId},
                {"oauth_token", token},
                {"oauth_nonce", SignatureGenerator.GenerateNonce()},
                {"oauth_signature_method", SignatureMethod},
                {"oauth_timestamp", SignatureGenerator.GetTimestamp()},
                {"oauth_version", "1.0"},
            };
            var parametersString = OAuthHelpers.ConstructQueryString(parameters);

            var signature = _signatureGenerator.GenerateSignature("GET", TumblrApi + "v2/user/info", parametersString, true);
            parameters.Set("oauth_signature", signature);

            return OAuthHelpers.BuildUri(TumblrApi, "v2/user/info", parameters);
        }

        private AuthenticationResult CreateAuthenticationResult(UserData userData)
        {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: "",
                userName: "this stuff not work",
                extraData: null
                );
        }

        private class UserData { }
    }
}

