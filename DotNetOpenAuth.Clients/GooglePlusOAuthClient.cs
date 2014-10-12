using System;
using System.Web;
using System.Collections.Generic;
using System.Collections.Specialized;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class GooglePlusOAuthClient : IAuthenticationClient {
        private readonly string _appId;
        private readonly string _appSecret;

        private const string OAuthUrl = "https://accounts.google.com/";
        private const string ApiUrl = "https://www.googleapis.com/";

        public static void RewriteRequest() { //TODO : help required
            var context = HttpContext.Current;
            var stateString = HttpUtility.UrlDecode(context.Request.QueryString["state"]);
            if (stateString == null || !stateString.Contains("__provider__=Google-Plus"))
                return;

            var query = HttpUtility.ParseQueryString(stateString);
            query.Add(context.Request.QueryString);
            context.RewritePath(context.Request.Path + "?" + query);
        }

        public GooglePlusOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Google-Plus"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var redirectUri = CreateRedirectUri(returnUrl);
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var authorizationCode = context.Request["code"];
            var accessToken = GetAccessToken(authorizationCode, context.Request.Url);
            var userData = GetUserData(accessToken.access_token);

            return CreateAuthenticationResult(userData);
        }

        #endregion

        private string CreateRedirectUri(Uri returnUrl) {
            return OAuthHelpers.BuildUri(OAuthUrl, "o/oauth2/auth", new NameValueCollection
            {
                {"client_id", _appId},
                {"redirect_uri", returnUrl.GetLeftPart(UriPartial.Path)},
                {"response_type", "code"},
                {"scope", "profile"},
                {"state", HttpUtility.UrlEncode(returnUrl.Query)}
            });
        }

        private AccessToken GetAccessToken(string authorizationCode, Uri returnUrl) {
            var param = new NameValueCollection
            {
                 { "client_id",     _appId },
                 { "client_secret", _appSecret },
                 { "code",          authorizationCode },
                 { "grant_type",    "authorization_code" },
                 { "redirect_uri",  returnUrl.GetLeftPart(UriPartial.Path) },
            };

            return OAuthHelpers.DeserializeJson<AccessToken>(OAuthHelpers.PostRequest(OAuthUrl, "o/oauth2/token", param));
        }

        private static UserData GetUserData(string accessToken) {
            var uri = OAuthHelpers.BuildUri(ApiUrl, "oauth2/v1/userinfo", new NameValueCollection 
            {
                { "access_token", accessToken } 
            });
            return OAuthHelpers.DeserializeJsonWithLoad<UserData>(uri);
        }

        private AuthenticationResult CreateAuthenticationResult(UserData userData) {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: userData.id,
                userName: userData.name,
                extraData:
                    new Dictionary<string, string>
                    {
                        { "LastName",  userData.family_name },
                        { "FirstName", userData.given_name }
                    });
        }

        private class AccessToken {
            public string access_token = null;
        }

        private class UserData {
            public string id = null;
            public string name = null;
            public string given_name = null;
            public string family_name = null;
        }
    }
}
