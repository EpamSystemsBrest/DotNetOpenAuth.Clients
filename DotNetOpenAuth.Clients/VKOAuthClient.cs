using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
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
            return CreateAuthenticationResult(accessToken, userData);
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

        private AccessToken GetAccessToken(HttpContextBase context) {
            var address = CreateBuildUri(context);
            return OAuthHelpers.DeserializeJsonWithLoad<AccessToken>(address);
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

        private static UserData GetUserData(AccessToken accessToken) {
            var address = CreateUsersGetUri(accessToken);
            return OAuthHelpers.DeserializeJsonWithLoad<UsersData>(address).response.First();
        }

        private static string CreateUsersGetUri(AccessToken accessToken) {
            var param = new NameValueCollection {
                {"uids", accessToken.user_id}
            };

            return OAuthHelpers.BuildUri(ApiUrl, "method/users.get", param);
        }

        private AuthenticationResult CreateAuthenticationResult(AccessToken accessToken, UserData userData) {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: accessToken.user_id,
                userName: userData.first_name + " " + userData.last_name,
                extraData:
                    new Dictionary<string, string>
                    {
                        {"LastName", userData.last_name},
                        {"FirstName", userData.first_name}
                    });
        }

        private class AccessToken {
            public string access_token = null;
            public string user_id = null;
        }

        private class UserData {
            public string uid = null;
            public string first_name = null;
            public string last_name = null;
        }

        private class UsersData {
            public UserData[] response = null;
        }
    }
}