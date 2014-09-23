using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Script.Serialization;
using DotNetOpenAuth.AspNet;

namespace Clients {
    public class VkOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://oauth.vk.com/";
        private const string ApiUrl = "https://api.vk.com/";
        private readonly string _appId;
        private readonly string _appSecret;

        public string ProviderName { get { return "VKontakte"; } }

        public VkOAuthClient(string appId, string appSecret) {
            _appId = appId;
            _appSecret = appSecret;
        }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var address = new Uri(new Uri(OAuthUrl),
                string.Format("authorize?client_id={0}&redirect_uri={1}&response_type=code&v=5.3",
                    _appId, HttpUtility.UrlEncode(returnUrl.AbsoluteUri)));

            HttpContext.Current.Response.Redirect(address.AbsoluteUri, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            try {
                var code = context.Request["code"];

                var address = new Uri(new Uri(OAuthUrl),
                    String.Format("access_token?client_id={0}&client_secret={1}&code={2}&redirect_uri={3}",
                        _appId, _appSecret, code, HttpUtility.UrlEncode(RemoveUriParameter(context.Request.Url, "code"))));

                var response = Load(address.AbsoluteUri);
                var accessToken = DeserializeJson<AccessToken>(response);

                address = new Uri(new Uri(ApiUrl),
                    String.Format("method/users.get?uids={0}&fields=photo_50", accessToken.user_id));

                response = Load(address.AbsoluteUri);
                var usersData = DeserializeJson<UsersData>(response);
                var userData = usersData.response.First();

                return new AuthenticationResult(
                    isSuccessful: true,
                    provider: (this as IAuthenticationClient).ProviderName,
                    providerUserId: accessToken.user_id,
                    userName: userData.first_name + " " + userData.last_name,
                    extraData: new Dictionary<string, string> { { "LastName", userData.last_name }, { "FirstName", userData.first_name } });
            } catch (Exception ex) {
                return new AuthenticationResult(ex);
            }
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

            return uri.GetLeftPart(UriPartial.Path) + "?" + valueCollection;
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