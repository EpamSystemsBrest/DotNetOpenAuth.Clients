using System;
using System.Web;
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
            var userData = GetUserData(accessToken);

            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userData);
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

        private string GetAccessToken(string authorizationCode, Uri returnUrl) {
            var param = new NameValueCollection
            {
                 { "client_id",     _appId },
                 { "client_secret", _appSecret },
                 { "code",          authorizationCode },
                 { "grant_type",    "authorization_code" },
                 { "redirect_uri",  returnUrl.GetLeftPart(UriPartial.Path) },
            };

            return OAuthHelpers.GetObjectWithPost(OAuthUrl, "o/oauth2/token", param).access_token;
        }

        private static UserInfo GetUserData(string accessToken) {
            var uri = OAuthHelpers.BuildUri(ApiUrl, "oauth2/v1/userinfo", new NameValueCollection 
            {
                { "access_token", accessToken } 
            });

            var response = OAuthHelpers.GetObjectFromAddress(uri);
            return new UserInfo {
                Id = response.id,
                UserName = response.name
            };
        }
    }
}
