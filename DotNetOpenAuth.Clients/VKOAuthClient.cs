using System;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class VkOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://oauth.vk.com/";
        private const string ApiUrl = "https://api.vk.com/";
        private readonly string _appId;
        private readonly string _appSecret;

        public VkOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Vk"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var uri = CreateAuthorizeUri(returnUrl);

            try {
                context.Response.Redirect(uri);
            }
            catch { //Tests context //TODO: @demns help wanted
                context.Response.RedirectLocation = uri;
            }
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context);
            var userData = GetUserData(accessToken);
            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userData);
        }

        #endregion IAuthenticationClient

        private string CreateAuthorizeUri(Uri returnUrl) {
            var param = new NameValueCollection {
                {"client_id", _appId},
                {"redirect_uri", HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"response_type", "code"},
                {"v", "5.3"}
            };

            return OAuthHelpers.BuildUri(OAuthUrl, "authorize", param);
        }

        private string GetAccessToken(HttpContextBase context) {
            var address = CreateBuildUri(context);
            var response = OAuthHelpers.GetObjectFromAddress(address);
            return response.user_id;
        }

        private string CreateBuildUri(HttpContextBase context) {
            var param = new NameValueCollection {
                {"client_id", _appId},
                {"client_secret", _appSecret},
                {"code", context.Request["code"]},
                {"redirect_uri", HttpUtility.UrlEncode(OAuthHelpers.RemoveUriParameter(context.Request.Url, "code"))}
            };

            return OAuthHelpers.BuildUri(OAuthUrl, "access_token", param);
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
                {"uids", userId}
            };

            return OAuthHelpers.BuildUri(ApiUrl, "method/users.get", param);
        }
    }
}