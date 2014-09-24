using System.Collections.Generic;
using DotNetOpenAuth.AspNet;
using System.Globalization;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace Clients {
    public class FlickrOAuthClient : IAuthenticationClient {
        private const string RequestTokenUrl = "https://www.flickr.com/services/oauth/request_token";
        private const string AccessTokenUrl = "https://www.flickr.com/services/oauth/access_token";
        private const string AuthorizeUrl = "https://www.flickr.com/services/oauth/authorize";
        private const string ApiUrl = "https://api.flickr.com";

        private readonly string _appId;
        private readonly string _appSecret;
        private string _oauthToken;
        private string _tokenSecret;

        public FlickrOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Flickr"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var rand = new Random();
            var nonce = rand.Next(999999).ToString(CultureInfo.InvariantCulture);

            var parameters = "oauth_callback=" + UrlHelper.Encode(returnUrl.AbsoluteUri)
                                + "&oauth_consumer_key=" + _appId
                                + "&oauth_nonce=" + nonce
                                + "&oauth_signature_method=HMAC-SHA1"
                                + "&oauth_timestamp=" + GetTimestamp()
                                + "&oauth_version=1.0";

            var signature = GenerateSignature("GET", RequestTokenUrl, parameters);

            var url = RequestTokenUrl + "?" + parameters + "&oauth_signature=" + signature;

            var client = new WebClient();
            var request = client.DownloadString(url);
            var requestToken = request.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries)[1];
            var requestTokenSecret = request.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries)[2];
            _tokenSecret = requestTokenSecret.Split('=')[1];
            var redirectUrl = AuthorizeUrl + "?" + requestToken;

            HttpContext.Current.Response.Redirect(redirectUrl, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var oauthVerifier = context.Request.QueryString["oauth_verifier"];
            _oauthToken = context.Request.QueryString["oauth_token"];

            var rand = new Random();
            var nonce = rand.Next(999999).ToString(CultureInfo.InvariantCulture);

            var parameters =
                        "oauth_consumer_key=" + _appId +
                        "&oauth_nonce=" + nonce +
                        "&oauth_signature_method=HMAC-SHA1" +
                        "&oauth_timestamp=" + GetTimestamp() +
                        "&oauth_token=" + _oauthToken +
                        "&oauth_verifier=" + oauthVerifier +
                        "&oauth_version=1.0";
            var sig = GenerateSignature("GET", AccessTokenUrl, parameters);
            var url = AccessTokenUrl + "?" + parameters + "&oauth_signature=" + sig;
            var client = new WebClient();
            var request = client.DownloadString(url);
            var userData = CreateUserInfo(request);
            return new AuthenticationResult(
                    isSuccessful: true,
                    provider: ProviderName,
                    providerUserId: userData.user_nsid,
                    userName: userData.username,
                    extraData:
                        new Dictionary<string, string>
                        {
                            {"FullName", userData.fullname},
                        });
        }

        private UserData CreateUserInfo(string request) {
            return new UserData {
                fullname = HttpUtility.ParseQueryString(request).Get("fullname"),
                user_nsid = HttpUtility.ParseQueryString(request).Get("user_nsid"),
                username = HttpUtility.ParseQueryString(request).Get("username")
            };
        }

        #endregion IAuthenticationClient

        private string GenerateSignature(string httpMethod, string apiEndpoint, string parameters) {
            var basestring = httpMethod + "&" + UrlHelper.Encode(apiEndpoint) + "&" + UrlHelper.Encode(parameters);

            var encoding = new ASCIIEncoding();

            //create key (request_token can be an empty string)
            var key = _appSecret + "&" + _tokenSecret;
            var keyByte = encoding.GetBytes(key);

            //create message to encrypt
            var messageBytes = encoding.GetBytes(basestring);
            string signature;
            //encrypt message using hmac-sha1 with the provided key
            using (var hmacsha1 = new HMACSHA1(keyByte)) {
                byte[] hashmessage = hmacsha1.ComputeHash(messageBytes);
                signature = Convert.ToBase64String(hashmessage);
            }
            return UrlHelper.Encode(signature);
        }

        private static string GetTimestamp() {
            return ((int)(DateTime.UtcNow - new DateTime(2000, 1, 1)).TotalSeconds).
                ToString(CultureInfo.InvariantCulture);
        }

        private class UserData {
            public string fullname;
            public string user_nsid;
            public string username;
        }
    }

    /// <summary> 
    /// URL encoding class.  Note: use at your own risk. 
    /// Written by: Ian Hopkins (http://www.lucidhelix.com) 
    /// Date: 2008-Dec-23 
    /// (Ported to C# by t3rse (http://www.t3rse.com)) 
    /// </summary> 
    public static class UrlHelper {
        public static string Encode(string str) {
            var charClass = String.Format("0-9a-zA-Z{0}", Regex.Escape("-_.!~*'()"));
            return Regex.Replace(str, String.Format("[^{0}]", charClass), EncodeEvaluator);
        }

        private static string EncodeEvaluator(Match match) {
            return (match.Value == " ") ? "+" : String.Format("%{0:X2}", Convert.ToInt32(match.Value[0]));
        }
    }
}
