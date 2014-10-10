using DotNetOpenAuth.AspNet;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;

namespace DotNetOpenAuth.Clients
{
    public class FacebookOAuthClient : IAuthenticationClient
    {
        public readonly string _appId;
        private readonly string _appSecret;

        public const string FbUrl = "https://www.facebook.com";
        private const string ApiUrl = "https://graph.facebook.com";

        public FacebookOAuthClient(string appId, string appSecret)
        {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Facebook"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var redirectUri = AuthClient.CreateRedirectionUri(FbUrl, "dialog/oauth", _appId, returnUrl);
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            var accessToken = GetAccessToken(context.Request["code"], context.Request.Url);
            var userData = GetUserData(accessToken);
            return CreateAuthenticationResult(userData);
        }

        #endregion

        private string GetAccessToken(string authorizationCode, Uri returnUrl)
        {
            var url = CreateAccessTokenUrl(authorizationCode, returnUrl);
            return HttpUtility.ParseQueryString(OAuthHelpers.Load(url)).Get("access_token");
        }

        private string CreateAccessTokenUrl(string authorizationCode, Uri returnUrl)
        {
            return OAuthHelpers.BuildUri(ApiUrl, "oauth/access_token", new NameValueCollection
            {
                {"client_id", _appId},
                {"client_secret", _appSecret},
                {"redirect_uri", HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"code", authorizationCode},
            });
        }

        private static FacebookOAuthClient.UserData GetUserData(string accessToken)
        {
            var uri = OAuthHelpers.BuildUri(ApiUrl, "me", new NameValueCollection
                {
                    { "access_token", accessToken } 
                
                });
            return OAuthHelpers.DeserializeJsonWithLoad<FacebookOAuthClient.UserData>(uri);
        }

        private AuthenticationResult CreateAuthenticationResult(FacebookOAuthClient.UserData userData)
        {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: userData.id,
                userName: userData.first_name + " " + userData.last_name,
                extraData:
                    new Dictionary<string, string>
                    {
                        {"LastName", userData.last_name},
                        {"FirstName", userData.first_name}
                    });
        }

        private class UserData
        {
            public string id = null;
            public string first_name = null;
            public string last_name = null;
        }
    }
}
