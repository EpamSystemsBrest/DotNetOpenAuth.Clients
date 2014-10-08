﻿using DotNetOpenAuth.AspNet;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;

namespace DotNetOpenAuth.Clients {
    public class FacebookOAuthClient : IAuthenticationClient {
        private readonly string _appId;
        private readonly string _appSecret;

        private const string FbUrl = "https://www.facebook.com";
        private const string ApiUrl = "https://graph.facebook.com";

        public FacebookOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Facebook"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var redirectUri = CreateRedirectionUri(returnUrl);
            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context.Request["code"], context.Request.Url);
            var userData = GetUserData(accessToken);
            return CreateAuthenticationResult(userData);
        }

        #endregion

        private string CreateRedirectionUri(Uri returnUrl) {
            return OAuthHelpers.BuildUri(FbUrl, "dialog/oauth", new NameValueCollection
            {
                {"client_id", _appId},
                {"redirect_uri", HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"response_type", "code"},
            });
        }

        private string GetAccessToken(string authorizationCode, Uri returnUrl) {
            var url = CreateAccessTokenUrl(authorizationCode, returnUrl);
            return HttpUtility.ParseQueryString(OAuthHelpers.Load(url)).Get("access_token");
        }

        private string CreateAccessTokenUrl(string authorizationCode, Uri returnUrl) {
            return OAuthHelpers.BuildUri(ApiUrl, "oauth/access_token", new NameValueCollection
            {
                {"client_id", _appId},
                {"client_secret", _appSecret},
                {"redirect_uri", HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"code", authorizationCode},
            });
        }

        private static UserData GetUserData(string accessToken) {
            var uri = OAuthHelpers.BuildUri(ApiUrl, "me", new NameValueCollection
                {
                    { "access_token", accessToken } 
                
                });
            return OAuthHelpers.DeserializeJsonWithLoad<UserData>(uri);
        }

        private AuthenticationResult CreateAuthenticationResult(UserData userData) {
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

        private class UserData {
            public string id = null;
            public string first_name = null;
            public string last_name = null;
        }
    }
}