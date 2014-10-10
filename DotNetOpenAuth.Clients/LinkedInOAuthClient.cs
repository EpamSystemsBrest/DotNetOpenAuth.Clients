using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients
{
    public class LinkedInOAuthClient : IAuthenticationClient
    {
        private const string OAuthUrl = "https://www.linkedin.com/";
        private const string ApiUrl = "https://api.linkedin.com/";

        private readonly string _appKey;
        private readonly string _appSecret;

        public LinkedInOAuthClient(string appKey, string secretKey)
        {
            _appKey = appKey;
            _appSecret = secretKey;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "LinkedIn"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            var uri = CreateRedirectionUri(returnUrl);
            context.Response.Redirect(uri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            var accessToken = GetAccessToken(context);
            var userData = GetUserData(accessToken);

            return CreateAuthenticationResult(userData);
        }

        #endregion

        private string CreateRedirectionUri(Uri returnUrl)
        {
            var param = new NameValueCollection {
                {"response_type", "code"},
                {"client_id", _appKey},
                {"state", Guid.NewGuid().ToString("N")},
                {"redirect_uri", HttpUtility.UrlEncode(returnUrl.AbsoluteUri)}
            };

            return OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/authorization", param);
        }

        private AccessToken GetAccessToken(HttpContextBase context)
        {
            var redirectUri =
                HttpUtility.UrlEncode(OAuthHelpers.RemoveUriParameter(context.Request.Url, "state", "code"));
            var address = CreateAccessTokenUri(context, redirectUri);

            return OAuthHelpers.DeserializeJsonWithLoad<AccessToken>(address);
        }

        private string CreateAccessTokenUri(HttpContextBase context, string redirectUri)
        {
            return OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/accessToken", new NameValueCollection
            {
                { "grant_type",    "authorization_code" },
                { "code",          context.Request["code"] },
                { "redirect_uri",  redirectUri },
                { "client_id",     _appKey},
                { "client_secret", _appSecret }
            });
        }

        private static UserData GetUserData(AccessToken accessToken)
        {
            var address = CreateUserDataUri(accessToken);
            return OAuthHelpers.DeserializeJsonWithLoad<UserData>(address);
        }

        private static string CreateUserDataUri(AccessToken accessToken)
        {
            var address = OAuthHelpers.BuildUri(ApiUrl, "v1/people/~", new NameValueCollection
            {
                {"oauth2_access_token", accessToken.access_token},
                {"format", "json"}
            });
            return address;
        }

        private AuthenticationResult CreateAuthenticationResult(UserData userData)
        {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: ProviderName,
                providerUserId: userData.headline,
                userName: userData.firstName + " " + userData.lastName,
                extraData: new Dictionary<string, string>());
        }

        private class AccessToken
        {
            public string access_token = null;
            public string expires_in = null;
        }

        private class UserData
        {
            public string firstName = null;
            public string headline = null;
            public string lastName = null;
        }
    }
}
