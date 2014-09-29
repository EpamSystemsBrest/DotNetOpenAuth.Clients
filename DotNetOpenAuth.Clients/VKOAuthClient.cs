using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
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
            var uri = OAuthHelpers.BuildUri(OAuthUrl, "authorize", new NameValueCollection() { 
                                { "client_id",     _appId },
                                { "redirect_uri" , HttpUtility.UrlEncode(returnUrl.AbsoluteUri) },
                                { "response_type", "code" },
                                { "v",             "5.3" } 
            });
            try {
                context.Response.Redirect(uri);
            } catch { //Tests context //TODO: @demns
                context.Response.RedirectLocation = uri;
            }
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            try {
                var accessToken = GetAccessToken(context);
                var userData = GetUserData(accessToken);
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
            } catch (WebException ex) {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            } catch (Exception ex) {
                return new AuthenticationResult(ex);
            }
        }

        #endregion IAuthenticationClient

        private AccessToken GetAccessToken(HttpContextBase context) {
            var code = context.Request["code"];
            var address = OAuthHelpers.BuildUri(OAuthUrl, "access_token", new NameValueCollection()
            {
                {"client_id", _appId},
                {"client_secret", _appSecret},
                {"code", code},
                {"redirect_uri", HttpUtility.UrlEncode(RemoveUriParameter(context.Request.Url, "code"))}
            });

            return DeserializeJson<AccessToken>(Load(address));
        }

        private static UserData GetUserData(AccessToken accessToken) {
            var address = OAuthHelpers.BuildUri(ApiUrl, "method/users.get", new NameValueCollection()
            {
                {"uids", accessToken.user_id}
            });

            var response = Load(address);
            return DeserializeJson<UsersData>(response).response.First();
        }

        private static string Load(string address) {
            var request = WebRequest.Create(address) as HttpWebRequest;
            using (var response = request.GetResponse() as HttpWebResponse) {
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    return reader.ReadToEnd();
                }
            }
        }

        private static string RemoveUriParameter(Uri uri, string uriParameterName) {
            var valueCollection = HttpUtility.ParseQueryString(uri.Query);

            if (!string.IsNullOrEmpty(valueCollection[uriParameterName]))
                valueCollection.Remove(uriParameterName);

            if (valueCollection.HasKeys())
                return uri.GetLeftPart(UriPartial.Path) + "?" + valueCollection;
            return uri.GetLeftPart(UriPartial.Path);
        }

        private static T DeserializeJson<T>(string input) {
            var serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>(input);
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