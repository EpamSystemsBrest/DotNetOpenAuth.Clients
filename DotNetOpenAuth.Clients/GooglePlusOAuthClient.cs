using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using DotNetOpenAuth.AspNet;


namespace DotNetOpenAuth.Clients {
    public class GooglePlusOAuthClient : IAuthenticationClient {

        private readonly string _appId;
        private readonly string _appSecret;

        private const string OAuthUrl = "https://accounts.google.com/";
        private const string ApiUrl = "https://www.googleapis.com/";

        public GooglePlusOAuthClient(string appId, string appSecret)
        {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "GooglePlus"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var pr = "&__provider__=" + OAuthHelpers.ParseQueryString(returnUrl.Query, "__provider__");
            var sid = "&__sid__=" + OAuthHelpers.ParseQueryString(returnUrl.Query, "__sid__");

            var redirectUri = OAuthHelpers.BuildUri(OAuthUrl, "o/oauth2/auth", new NameValueCollection
            {
                {"client_id", _appId},
                {"redirect_uri", returnUrl.GetLeftPart(UriPartial.Path)},
                {"response_type", "code"},                
                {"scope", "profile"},
                {"state", HttpUtility.UrlEncode(pr+sid)}
            });

            context.Response.Redirect(redirectUri);
        }
           
        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            try
            {
                var authorizationCode = context.Request["code"];
                var accessToken = GetAccessToken(authorizationCode, context.Request.Url);
                var userData = GetUserData(accessToken.access_token);

                return new AuthenticationResult(
                        isSuccessful: true,
                        provider: ProviderName,
                        providerUserId: userData.id,
                        userName: userData.name,
                        extraData:
                            new Dictionary<string, string>
                        {
                            {"LastName", userData.family_name},
                            {"FirstName", userData.given_name}
                        });
            }
            catch (WebException ex)
            {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            }
            catch (Exception ex)
            {
                return new AuthenticationResult(ex);
            }
        }

        #endregion
        
        public static void RewriteRequest()
        {
            var ctx = HttpContext.Current;
            var stateString = HttpUtility.UrlDecode(ctx.Request.QueryString["state"]);
            if (stateString == null || !stateString.Contains("__provider__=GooglePlus"))
                return;
            var q = HttpUtility.ParseQueryString(stateString);
            q.Add(ctx.Request.QueryString);
            q.Remove("state");
            ctx.RewritePath(ctx.Request.Path + "?" + q);
        }

        private AccessToken GetAccessToken(string authorizationCode, Uri returnUrl)
        {
            var param = new NameValueCollection
            {
                 { "grant_type", "authorization_code" },
                 { "code", authorizationCode },
                 { "client_id", _appId },
                 { "client_secret", _appSecret },
                 { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path)},
            };

            // TODO :
            var request = WebRequest.Create(new UriBuilder(OAuthUrl){Path = "o/oauth2/token"}.ToString());
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            var dataPost = Encoding.ASCII.GetBytes(OAuthHelpers.ConstructQueryString(param));
            request.ContentLength = dataPost.Length;

            using (var stream = request.GetRequestStream())
            {
                stream.Write(dataPost, 0, dataPost.Length);
            }

            var response = (HttpWebResponse)request.GetResponse();
            var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
            
            return OAuthHelpers.DeserializeJson<AccessToken>(responseString);
        }

        private static UserData GetUserData(string accessToken)
        {
            var uri = OAuthHelpers.BuildUri(ApiUrl, "oauth2/v1/userinfo", new NameValueCollection { { "access_token", accessToken } });
            return OAuthHelpers.DeserializeJsonWithLoad<UserData>(uri);
        }

        private class AccessToken
        {
            public string access_token = null;
        }

        private class UserData
        {
            public string id = null;
            public string name = null;
            public string given_name = null;
            public string family_name = null;
        }
    }
}
