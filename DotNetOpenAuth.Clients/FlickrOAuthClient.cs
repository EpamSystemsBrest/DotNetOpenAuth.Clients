using System.Collections.Generic;
using DotNetOpenAuth.AspNet;
using System.Globalization;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace DotNetOpenAuth.Clients {
    public class FlickrOAuthClient : IAuthenticationClient {
        private const string RequestTokenUrl = "https://www.flickr.com/services/oauth/request_token";
        private const string AccessTokenUrl = "https://www.flickr.com/services/oauth/access_token";
        private const string AuthorizeUrl = "https://www.flickr.com/services/oauth/authorize";
        private const string ApiUrl = "https://api.flickr.com";
        private const string SignatureMethod = "HMAC-SHA1";

        private readonly string _appId;
        private readonly string _appSecret;
        private string _tokenSecret;
        private readonly Random _rand = new Random();

        public FlickrOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Flickr"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var url = CreateRequestTokenUrl(returnUrl);
            var request = GetRequestStringFromUrl(url);
            var requestToken = GetValueFromRequest(request, "oauth_token");
            _tokenSecret = GetValueFromRequest(request, "oauth_token_secret");

            HttpContext.Current.Response.Redirect(AuthorizeUrl + "?oauth_token=" + requestToken, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var url = CreateUserInfoUrl(context);
            var request = GetRequestStringFromUrl(url);
            var userData = UserData.CreateUserInfo(request);
            return CreateAuthenticationResult(userData);
        }

        #endregion IAuthenticationClient

        private string CreateRequestTokenUrl(Uri returnUrl) {
            var parameters = "oauth_callback=" + Encode(returnUrl.AbsoluteUri) +
                             "&oauth_consumer_key=" + _appId +
                             "&oauth_nonce=" + GenerateNonce() +
                             "&oauth_signature_method=" + SignatureMethod +
                             "&oauth_timestamp=" + GetTimestamp() +
                             "&oauth_version=1.0";

            var signature = GenerateSignature("GET", RequestTokenUrl, parameters, true);

            return RequestTokenUrl + "?" + parameters + "&oauth_signature=" + signature;
        }

        private static string GetRequestStringFromUrl(string url) {
            return new WebClient().DownloadString(url);
        }

        private static string GetValueFromRequest(string request, string value) {
            return HttpUtility.ParseQueryString(request).Get(value);
        }

        private AuthenticationResult CreateAuthenticationResult(UserData userData) {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: userData.UserNsid,
                userName: userData.Username,
                extraData:
                    new Dictionary<string, string>
                    {
                        {"FullName", userData.Fullname},
                    });
        }

        private string CreateUserInfoUrl(HttpContextBase context) {
            var oauthVerifier = context.Request.QueryString["oauth_verifier"];
            var oauthToken = context.Request.QueryString["oauth_token"];

            var parameters = "oauth_consumer_key=" + _appId +
                             "&oauth_nonce=" + GenerateNonce() +
                             "&oauth_signature_method=HMAC-SHA1" +
                             "&oauth_timestamp=" + GetTimestamp() +
                             "&oauth_token=" + oauthToken +
                             "&oauth_verifier=" + oauthVerifier +
                             "&oauth_version=1.0";

            var signature = GenerateSignature("GET", AccessTokenUrl, parameters);
            return AccessTokenUrl + "?" + parameters + "&oauth_signature=" + signature;
        }

        private string GenerateSignature(string httpMethod, string apiEndpoint, string parameters, bool getToken = false) {
            var basestring = httpMethod + "&" + Encode(apiEndpoint) + "&" + Encode(parameters);

            var encoding = new ASCIIEncoding();

            var key = getToken ? _appSecret + "&" : _appSecret + "&" + _tokenSecret;
            var keyByte = encoding.GetBytes(key);

            var messageBytes = encoding.GetBytes(basestring);
            string signature;
            using (var hmacsha1 = new HMACSHA1(keyByte)) {
                byte[] hashmessage = hmacsha1.ComputeHash(messageBytes);
                signature = Convert.ToBase64String(hashmessage);
            }
            return Encode(signature);
        }

        private static string GetTimestamp() {
            return ((int)(DateTime.UtcNow - new DateTime(2000, 1, 1)).TotalSeconds).
                ToString(CultureInfo.InvariantCulture);
        }

        private string GenerateNonce() {
            return _rand.Next(999999).ToString(CultureInfo.InvariantCulture);
        }

        private class UserData {
            public string Fullname;
            public string UserNsid;
            public string Username;

            public static UserData CreateUserInfo(string queryString) {
                return new UserData {
                    Fullname = HttpUtility.ParseQueryString(queryString).Get("fullname"),
                    UserNsid = HttpUtility.ParseQueryString(queryString).Get("user_nsid"),
                    Username = HttpUtility.ParseQueryString(queryString).Get("username")
                };
            }
        }

        private static string Encode(string str) {
            var charClass = String.Format("0-9a-zA-Z{0}", Regex.Escape("-_.!~*'()"));
            return Regex.Replace(str, String.Format("[^{0}]", charClass), EncodeEvaluator);
        }

        private static string EncodeEvaluator(Match match) {
            return (match.Value == " ") ? "+" : String.Format("%{0:X2}", Convert.ToInt32(match.Value[0]));
        }
    }
}
