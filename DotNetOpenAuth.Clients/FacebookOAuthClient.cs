using DotNetOpenAuth.AspNet;
using System;
using System.Collections.Specialized;
using System.Web;

namespace DotNetOpenAuth.Clients {
    public class FacebookOAuthClient : IAuthenticationClient {
        public readonly string AppId;
        private readonly string _appSecret;

        public const string FbUrl = "https://www.facebook.com";
        private const string ApiUrl = "https://graph.facebook.com";

        public FacebookOAuthClient(string appId, string appSecret) {
            AppId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Facebook"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var redirectUri = AuthClient.CreateRedirectionUri(FbUrl, "dialog/oauth", AppId, returnUrl);
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context.Request["code"], context.Request.Url);
            var userData = GetUserData(accessToken);
            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userData);
        }

        #endregion

        private string GetAccessToken(string authorizationCode, Uri returnUrl) {
            var url = CreateAccessTokenUrl(authorizationCode, returnUrl);
            return HttpUtility.ParseQueryString(OAuthHelpers.Load(url)).Get("access_token");
        }

        private string CreateAccessTokenUrl(string authorizationCode, Uri returnUrl) {
            return OAuthHelpers.BuildUri(ApiUrl, "oauth/access_token", new NameValueCollection
            {
                {"client_id", AppId},
                {"client_secret", _appSecret},
                {"redirect_uri", HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"code", authorizationCode},
            });
        }

        private static UserInfo GetUserData(string accessToken) {
            var uri = CreateUserInfoUri(accessToken);
            var response = OAuthHelpers.GetObjectFromAddress(uri);

            return new UserInfo {
                Id = response.id,
                UserName = response.first_name + " " + response.last_name
            };
        }

        private static string CreateUserInfoUri(string accessToken) {
            return OAuthHelpers.BuildUri(ApiUrl, "me", new NameValueCollection
            {
                { "access_token", accessToken } 
                
            });
        }
    }
}
