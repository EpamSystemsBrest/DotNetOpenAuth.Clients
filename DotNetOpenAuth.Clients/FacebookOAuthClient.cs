using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients
{
    public class FacebookOAuthClient : IAuthenticationClient
    {
        private readonly string _appId;
        private readonly string _appSecret;

        private const string FbUrl = "https://www.facebook.com";
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
            var redirectUri = OAuthHelpers.BuildUri(FbUrl, "dialog/oauth", new NameValueCollection
            {
                {"client_id", _appId},
                {"redirect_uri",  HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"response_type", "code"},                
            });

            context.Response.Redirect(redirectUri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            try
            {
                var authorizationCode = context.Request["code"];
                var accessToken = GetAccessToken(authorizationCode, context.Request.Url);
                var userData = GetUserData(accessToken);

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
            catch (WebException ex)
            {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            }
            catch (Exception ex)
            {
                return new AuthenticationResult(ex);
            }
        }

        #endregion 

        private string GetAccessToken(string authorizationCode, Uri returnUrl)
        {
            var url = OAuthHelpers.BuildUri(ApiUrl, "oauth/access_token", new NameValueCollection
            {
                {"client_id", _appId},
                {"client_secret", _appSecret },  
                {"redirect_uri",  HttpUtility.UrlEncode(returnUrl.AbsoluteUri)},
                {"code", authorizationCode},         
            });

            return OAuthHelpers.ParseQueryString(OAuthHelpers.Load((url)), "access_token");
        }

        private static UserData GetUserData(string accessToken)
        {
            var uri = OAuthHelpers.BuildUri(ApiUrl, "me", new NameValueCollection { { "access_token", accessToken } });
            return OAuthHelpers.DeserializeJsonWithLoad<UserData>(uri);
        }

        private class UserData
        {
            public string id = null;
            public string first_name = null;
            public string last_name = null;
        }
    }
}
