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

        private const string OAuthUrl = "https://accounts.google.com/o/oauth2/";
        private const string ApiUrl = "https://www.googleapis.com/oauth2/v1/";

        public GooglePlusOAuthClient(string appId, string appSecret)
        {
            this._appId = appId;
            this._appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "GooglePlus"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var pr = "&__provider__=" + OAuthHelpers.ParseQueryString(returnUrl.Query, "__provider__");
            var sid = "&__sid__=" + OAuthHelpers.ParseQueryString(returnUrl.Query, "__sid__");

            var redirectUri = BuildUri(OAuthUrl, "auth", new NameValueCollection()
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
                string authorizationCode = context.Request["code"];
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
            var param = new NameValueCollection()
            {
                 { "grant_type", "authorization_code" },
                 { "code", authorizationCode },
                 { "client_id", _appId },
                 { "client_secret", _appSecret },
                 { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path)},
            };

            var request = WebRequest.Create(BuildUri(OAuthUrl, "token"));
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
            var uri = BuildUri(ApiUrl, "userinfo", new NameValueCollection { { "access_token", accessToken } });
            return OAuthHelpers.DeserializeJsonOnLoad<UserData>(uri);
        }

        private static string BuildUri(string url, string path, NameValueCollection query = null)
        {
            if (query == null)
                return string.Format("{0}{1}", url, path);

            return string.Format("{0}{1}?{2}", url, path, OAuthHelpers.ConstructQueryString(query));
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
