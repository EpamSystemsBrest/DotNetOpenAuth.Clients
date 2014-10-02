using System;
using System.Web;
using DotNetOpenAuth.AspNet;
using System.Net;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Globalization;
using System.Text.RegularExpressions;

namespace DotNetOpenAuth.Clients {
    public class TumblrOAuthClient : IAuthenticationClient {
        private const string RequestTokenUrl = "http://www.tumblr.com/oauth/request_token";
        private const string AccessTokenUrl = "http://www.tumblr.com/oauth/access_token";
        private const string AuthorizeUrl = "http://www.tumblr.com/oauth/authorize";
        private const string SignatureMethod = "HMAC-SHA1";
        private const string OAuthVersion = "1.0";

        private readonly string _appId;
        private readonly string _appSecret;
        private string _tokenSecret;
        private string _token;
        private readonly Random _rand = new Random();


        public TumblrOAuthClient(string appId, string appSecret)
        {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Tumblr"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var url = CreateRequestTokenUrl(returnUrl);
            var request = GetRequestStringFromUrl(url);
            _token = GetValueFromRequest(request, "oauth_token");
            _tokenSecret = GetValueFromRequest(request, "oauth_token_secret");

            HttpContext.Current.Response.Redirect(AuthorizeUrl + "?oauth_token=" + _token, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) 
        {
            //var request = GetRequestStringFromUrl(CreateAuthorizeUrl());
            //var userData = UserData.CreateUserInfo(request);
            return CreateAuthenticationResult();
        }

        #endregion IAuthenticationClient

        private string CreateRequestTokenUrl(Uri returnUrl)
        {
            var parameters = "oauth_callback=" + Encode(returnUrl.AbsoluteUri) +
                             "&oauth_consumer_key=" + _appId +
                             "&oauth_nonce=" + GenerateNonce() +
                             "&oauth_signature_method=" + SignatureMethod +
                             "&oauth_timestamp=" + GetTimestamp() +
                             "&oauth_version=" + OAuthVersion;

            var signature = GenerateSignature("GET", RequestTokenUrl, parameters, true);

            return RequestTokenUrl + "?" + parameters + "&oauth_signature=" + signature;
        }

        private string CreateAccessTokenUrl(HttpContextBase context)
        {
            var oauthVerifier = context.Request.QueryString["oauth_verifier"];
            var oauthToken = context.Request.QueryString["oauth_token"];

            var parameters = "oauth_consumer_key=" + _appId +
                             "&oauth_nonce=" + GenerateNonce() +
                             "&oauth_signature_method=" + SignatureMethod +
                             "&oauth_timestamp=" + GetTimestamp() +
                             "&oauth_token=" + oauthToken +
                             "&oauth_verifier=" + oauthVerifier +
                             "&oauth_version=" + OAuthVersion;

            var signature = GenerateSignature("GET", AccessTokenUrl, parameters);
            return AccessTokenUrl + "?" + parameters + "&oauth_signature=" + signature;
        }

        //
        //
        //    var parameters = "oauth_consumer_key=" + _appId +
        //                    "&oauth_consumer_secret =" + _appSecret +
        //                    "&oauth_token=" + _token +
        //                    "&oauth_token_secret =" + _tokenSecret;

        //   
        //

        private static string GetRequestStringFromUrl(string url) 
        {
            return new WebClient().DownloadString(url);
        }

        private static string GetValueFromRequest(string request, string value) 
        {
            return HttpUtility.ParseQueryString(request).Get(value);
        }

        private AuthenticationResult CreateAuthenticationResult() 
        {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: "0",
                userName: "MyName",
                extraData: null);
        }     

        private string GenerateSignature(string httpMethod, string apiEndpoint, string parameters, bool getToken = false) 
        {
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
            return ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds)
                        .ToString(CultureInfo.InvariantCulture);
        }

        private string GenerateNonce() {
            return _rand.Next(999999).ToString(CultureInfo.InvariantCulture);
        }

        private class UserData {
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
