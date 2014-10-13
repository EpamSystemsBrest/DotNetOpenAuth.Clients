using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
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
            var parameters = new NameValueCollection
            {
                {"oauth_consumer_key", _appId},
                {"oauth_nonce", SignatureGenerator.GenerateNonce()},
                {"oauth_signature_method", SignatureMethod},
                {"oauth_timestamp", SignatureGenerator.GetTimestamp()},
                {"oauth_token", token},
                {"oauth_version", "1.0"},
            };
            var parametersString = OAuthHelpers.ConstructQueryString(parameters);

            var signature = _signatureGenerator.GenerateSignature("GET", TumblrApi + "v2/user/info", parametersString);

            parameters.Set("oauth_signature", signature);

            var auth = "OAuth" + ConstructQueryStringForComma(parameters);

            var response = LoadWithAuthHeader(OAuthHelpers.BuildUri(TumblrApi, "v2/user/info", parameters), auth);

            return OAuthHelpers.DeserializeJson<UserData>(response);
        }

        public static String ConstructQueryStringForComma(NameValueCollection parameters)
        {
            return String.Join(",",
                parameters.Cast<string>().Select(parameter => parameter + "=" + parameters[parameter])
                );
        }

        public static string LoadWithAuthHeader(string address, string auth)
        {
            try
            {
                var request = WebRequest.Create(address);
                request.Method = "GET";

                request.Headers.Add("Authorization", auth);

                using (var response = request.GetResponse())
                {
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
            catch (WebException ex)
            {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            }
        }

        private AuthenticationResult CreateAuthenticationResult(UserData userData)
        {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: userData.response.user.blogs[0].url,
                userName: userData.response.user.name,
                extraData: null
                );
        }

        public class UserData
        {
            public Meta meta { get; set; }
            public Response response { get; set; }
        }

        public class Meta
        {
            public int status { get; set; }
            public string msg { get; set; }
        }

        public class Response
        {
            public User user { get; set; }
        }

        public class User
        {
            public string name { get; set; }
            public int likes { get; set; }
            public int following { get; set; }
            public string default_post_format { get; set; }
            public Blog[] blogs { get; set; }
        }

        public class Blog
        {
            public string title { get; set; }
            public string name { get; set; }
            public int posts { get; set; }
            public string url { get; set; }
            public int updated { get; set; }
            public string description { get; set; }
            public bool is_nsfw { get; set; }
            public bool ask { get; set; }
            public string ask_page_title { get; set; }
            public bool ask_anon { get; set; }
            public bool followed { get; set; }
            public bool can_send_fan_mail { get; set; }
            public bool share_likes { get; set; }
            public int likes { get; set; }
            public bool twitter_enabled { get; set; }
            public bool twitter_send { get; set; }
            public string facebook_opengraph_enabled { get; set; }
            public string tweet { get; set; }
            public string facebook { get; set; }
            public int followers { get; set; }
            public bool primary { get; set; }
            public bool admin { get; set; }
            public int messages { get; set; }
            public int queue { get; set; }
            public int drafts { get; set; }
            public string type { get; set; }
        }

    }
}

