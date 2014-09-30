using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Text;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class LinkedInOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://www.linkedin.com/";
        private const string ApiUrl = "https://api.linkedin.com/";

        private readonly string _appKey;
        private readonly string _appSecret;

        public LinkedInOAuthClient(string appKey, string secretKey) {
            _appKey = appKey;
            _appSecret = secretKey;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "LinkedIn"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var uri = OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/authorization", new NameValueCollection()
            {
                                { "response_type", "code"},
                                { "client_id",     _appKey },
                                { "state",         Guid.NewGuid().ToString("N")   },
                                { "redirect_uri" , HttpUtility.UrlEncode(returnUrl.AbsoluteUri) }
            });

            try {
                context.Response.Redirect(uri);
            } catch { //Tests context //TODO: @demns
                context.Response.RedirectLocation = uri;
            }
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context);
            var userData = GetUserData(accessToken);

            try {
                return new AuthenticationResult(
                    isSuccessful: true,
                    provider: ProviderName,
                    providerUserId: userData.headline,
                    userName: userData.firstName + userData.lastName,
                    extraData:
                        new Dictionary<string, string>());
            } catch (WebException ex) {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            } catch (Exception ex) {
                return new AuthenticationResult(ex);
            }
        }

        #endregion

        private AccessToken GetAccessToken(HttpContextBase context) {
            var redirectUri =
                HttpUtility.UrlEncode(OAuthHelpers.RemoveUriParameter(context.Request.Url, "state", "code"));
            var address = OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/accessToken", new NameValueCollection()
            {
                {"grant_type",    "authorization_code"},
                {"code",          context.Request["code"]},
                {"redirect_uri",  redirectUri},
                {"client_id",     _appKey},
                {"client_secret", _appSecret}
            });

            return OAuthHelpers.DeserializeJson<AccessToken>(OAuthHelpers.Load(address));
        }

        private static UserData GetUserData(AccessToken accessToken) {
            var address = OAuthHelpers.BuildUri(ApiUrl, "v1/people/~", new NameValueCollection()
            {
                {"oauth2_access_token", accessToken.access_token},
                {"format",              "json"}
            });

            return OAuthHelpers.DeserializeJson<UserData>(OAuthHelpers.Load(address));
        }

        private class AccessToken {
            public string access_token = null;
            public string expires_in = null;
        }

        private class UserData {
            public string firstName = null;
            public string headline = null;
            public string lastName = null;
        }
    }
}
