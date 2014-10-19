using System;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class InstagramOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://api.instagram.com/";
        private const string OauthAccessTokenPath = "/oauth/access_token/";
        private const string OauthAuthorizePath = "/oauth/authorize/";

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
            _redirectUri = returnUrl.AbsoluteUri;

            var redirectUri = AuthClient.CreateRedirectionUri(OAuthUrl, OauthAuthorizePath, _clientId, returnUrl);
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessInfo = GetAccessInfo(context.Request["code"]);
            return OAuthHelpers.CreateAuthenticationResult(ProviderName, accessInfo);
        }

        #endregion

        private UserInfo GetAccessInfo(string code) {
            var param = new NameValueCollection {
                { "client_id",      _clientId },
                { "client_secret",  _clientSecret },
                { "code",           code },
                { "grant_type",     "authorization_code" },
                { "redirect_uri",   _redirectUri }
            };

            var url = OAuthHelpers.BuildUri(OAuthUrl, OauthAccessTokenPath, new NameValueCollection());
            var response = OAuthHelpers.GetObjectWithPost(url, param);

            return new UserInfo {
                Id = response.user.id,
                UserName = response.user.full_name
            };
        }
    }
}
