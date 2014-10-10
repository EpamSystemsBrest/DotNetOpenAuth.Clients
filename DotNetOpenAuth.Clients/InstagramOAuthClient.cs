using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients
{
    public class InstagramOAuthClient : IAuthenticationClient
    {
        private const string OAuthUrl = "https://api.instagram.com/";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private string _redirectUri;

        public InstagramOAuthClient(string clientId, string clientSecret)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Instagram"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var redirectUri = AuthClient.CreateRedirectionUri(OAuthUrl, "/oauth/authorize/", _clientId, returnUrl);
            _redirectUri = returnUrl.AbsoluteUri;
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            var accessInfo = GetAccessInfo(context);
            return CreateAuthenticationResult(accessInfo);
        }

        #endregion

        private AccessInfo GetAccessInfo(HttpContextBase context)
        {
            var param = new NameValueCollection
            {
                {"client_id", _clientId},
                {"client_secret", _clientSecret},
                {"grant_type", "authorization_code"},
                {"redirect_uri", _redirectUri},
                {"code", context.Request["code"]}
            };
            return OAuthHelpers.DeserializeJson<AccessInfo>(
                OAuthHelpers.PostRequest(OAuthUrl, "/oauth/access_token/", param));
        }

        private AuthenticationResult CreateAuthenticationResult(AccessInfo accessInfo)
        {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: accessInfo.user.id,
                userName: accessInfo.user.username,
                extraData: new Dictionary<string, string>());
        }

        private class AccessInfo
        {
            public string access_token { get; set; }
            public User user { get; set; }
        }

        private class User
        {
            public string id { get; set; }
            public string username { get; set; }
            public string full_name { get; set; }
            public string profile_picture { get; set; }
        }
    }
}
