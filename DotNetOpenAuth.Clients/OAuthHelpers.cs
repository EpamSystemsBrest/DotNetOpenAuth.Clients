using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using DotNetOpenAuth.AspNet;
using Newtonsoft.Json.Linq;

namespace DotNetOpenAuth.Clients {
    public static class OAuthHelpers {
        public static string BuildUri(string url, string path, NameValueCollection query) {
            var uriBuilder = new UriBuilder(url) {
                Path = path,
                Query = ConstructQueryString(query)
            };
            return uriBuilder.ToString();
        }

        public static String ConstructQueryString(NameValueCollection parameters, string separator = "&") {
            return String.Join(separator,
                parameters.Cast<string>().Select(parameter => parameter + "=" + parameters[parameter])
                );
        }

        public static string Load(string address) {
            using (var webClient = new WebClient()) {
                return Encoding.UTF8.GetString(webClient.DownloadData(address));
            }
        }

        public static string AuthorizationLoad(string address, string auth) {
            using (var webClient = new WebClient()) {
                webClient.Headers[HttpRequestHeader.Authorization] = auth;
                return Encoding.UTF8.GetString(webClient.DownloadData(address));
            }
        }

        public static string PostRequest(string url, NameValueCollection param) {
            using (var wb = new WebClient()) {
                return Encoding.UTF8.GetString(wb.UploadValues(url, "POST", param));
            }
        }
        public static string GetValueFromRequest(string request, string value) {
            return HttpUtility.ParseQueryString(request).Get(value);
        }

        public static dynamic GetObjectFromAddress(string address) {
            return JObject.Parse(Load(address));
        }

        public static dynamic GetObjectWithPost(string url, NameValueCollection param) {
            return JObject.Parse(PostRequest(url, param));
        }

        public static AuthenticationResult CreateAuthenticationResult(string providerName, UserInfo userInfo) {
            return new AuthenticationResult(
                isSuccessful: true,
                provider: providerName,
                providerUserId: userInfo.Id,
                userName: userInfo.UserName,
                extraData:
                    new Dictionary<string, string>()
                    );
        }
    }
}
