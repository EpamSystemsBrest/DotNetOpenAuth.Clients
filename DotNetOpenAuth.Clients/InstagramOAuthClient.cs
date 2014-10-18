using System;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class InstagramOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://api.instagram.com/";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private string _redirectUri;

        public InstagramOAuthClient(string clientId, string clientSecret) {
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Instagram"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var redirectUri = AuthClient.CreateRedirectionUri(OAuthUrl, "/oauth/authorize/", _clientId, returnUrl);
            _redirectUri = returnUrl.AbsoluteUri;
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessInfo = GetAccessInfo(context);
            return OAuthHelpers.CreateAuthenticationResult(ProviderName, accessInfo);
        }

        #endregion

        private UserInfo GetAccessInfo(HttpContextBase context) {
            var param = new NameValueCollection {
                { "client_id",      _clientId },
                { "client_secret",  _clientSecret },
                { "grant_type",     "authorization_code" },
                { "redirect_uri",   _redirectUri },
                { "code",           context.Request["code"] }
            };

            var response = OAuthHelpers.GetObjectWithPost(OAuthUrl, "/oauth/access_token/", param);

            return new UserInfo {
                Id = response.user.id,
                UserName = response.user.full_name
            };
        }
    }
}
