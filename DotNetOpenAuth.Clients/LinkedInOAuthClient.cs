using System;
using System.Collections.Specialized;
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
            var uri = CreateRedirectionUri(returnUrl);
            context.Response.Redirect(uri);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context);
            var userData = GetUserData(accessToken);

            return OAuthHelpers.CreateAuthenticationResult(ProviderName, userData);
        }

        #endregion

        private string CreateRedirectionUri(Uri returnUrl) {
            var param = new NameValueCollection {
                { "response_type",  "code" },
                { "client_id",      _appKey },
                { "state",          Guid.NewGuid().ToString("N") },
                { "redirect_uri",   HttpUtility.UrlEncode(returnUrl.AbsoluteUri) }
            };

            return OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/authorization", param);
        }

        private string GetAccessToken(HttpContextBase context) {
            var redirectUri =
                HttpUtility.UrlEncode(OAuthHelpers.RemoveUriParameter(context.Request.Url, "state", "code"));
            var address = CreateAccessTokenUri(context, redirectUri);

            return OAuthHelpers.GetObjectFromAddress(address).access_token;
        }

        private string CreateAccessTokenUri(HttpContextBase context, string redirectUri) {
            return OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/accessToken", new NameValueCollection
            {
                { "grant_type",    "authorization_code" },
                { "code",          context.Request["code"] },
                { "redirect_uri",  redirectUri },
                { "client_id",     _appKey},
                { "client_secret", _appSecret }
            });
        }

        private static UserInfo GetUserData(string accessToken) {
            var address = CreateUserDataUri(accessToken);
            var response = OAuthHelpers.GetObjectFromAddress(address);
            var url = new Uri(response.siteStandardProfileRequest.url.ToString());
            var id = HttpUtility.ParseQueryString(url.Query).Get("id");
            return new UserInfo {
                Id = id,
                UserName = String.Format("{0} {1}", response.firstName, response.lastName)
            };
        }

        private static string CreateUserDataUri(string accessToken) {
            return OAuthHelpers.BuildUri(ApiUrl, "v1/people/~", new NameValueCollection {
                { "oauth2_access_token", accessToken },
                { "format",              "json" }
            });
        }
    }
}
