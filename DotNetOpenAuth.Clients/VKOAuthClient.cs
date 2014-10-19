using System;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class VkOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://oauth.vk.com/";
        private const string ApiUrl = "https://api.vk.com/";
        private const string AuthorizePath = "/authorize/";
        private const string OAuthTokenPath = "/access_token/";
        private const string OAuthGetUsersPath = "method/users.get";

        private readonly string _appId;
        private readonly string _appSecret;
        private string _redirectUri;

        public VkOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Vk"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            _redirectUri = HttpUtility.UrlEncode(returnUrl.AbsoluteUri);

            var redirectUri = AuthClient.CreateRedirectionUri(OAuthUrl, AuthorizePath, _appId, returnUrl);
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context.Request["code"]);
            var userData = GetUserData(accessToken);
            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userData);
        }

        #endregion IAuthenticationClient

        private string GetAccessToken(string code) {
            var address = CreateBuildUri(code);
            return OAuthHelpers.GetObjectFromAddress(address).user_id;
        }

        private string CreateBuildUri(string code) {
            var param = new NameValueCollection {
                { "client_id",       _appId },
                { "client_secret",   _appSecret },
                { "code",            code },
                { "redirect_uri",    _redirectUri }
            };

            return OAuthHelpers.BuildUri(OAuthUrl, OAuthTokenPath, param);
        }

        private static UserInfo GetUserData(string userId) {
            var address = CreateUserInfoUri(userId);
            var response = OAuthHelpers.GetObjectFromAddress(address);
            var user = response.response[0];
            return new UserInfo {
                Id = user.uid,
                UserName = String.Format("{0} {1}", user.first_name, user.last_name)
            };
        }

        private static string CreateUserInfoUri(string userId) {
            var param = new NameValueCollection {
                { "uids", userId }
            };

            return OAuthHelpers.BuildUri(ApiUrl, OAuthGetUsersPath, param);
        }
    }
}