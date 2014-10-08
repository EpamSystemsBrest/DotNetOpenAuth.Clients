using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Script.Serialization;

namespace DotNetOpenAuth.Clients {
    public static class OAuthHelpers {
        public static string BuildUri(string url, string path, NameValueCollection query) {
            var uriBuilder = new UriBuilder(url) {
                Path = path,
                Query = ConstructQueryString(query)
            };
            return uriBuilder.ToString();
        }

        public static String ConstructQueryString(NameValueCollection parameters) {
            return String.Join("&",
                parameters.Cast<string>().Select(parameter => parameter + "=" + parameters[parameter])
                );
        }

        public static string RemoveUriParameter(Uri uri, params string[] uriParameterName) {
            var valueCollection = HttpUtility.ParseQueryString(uri.Query);

            foreach (var str in uriParameterName) {
                valueCollection.Remove(str);
            }

            if (valueCollection.HasKeys())
                return uri.GetLeftPart(UriPartial.Path) + "?" + valueCollection;

            return uri.GetLeftPart(UriPartial.Path);
        }

        public static string Load(string address) { //TODO: check for webclient (culture problems)
            var request = WebRequest.Create(address);
            using (var response = request.GetResponse()) {
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    return reader.ReadToEnd();
                }
            }
        }

        public static T DeserializeJson<T>(string input) {
            var serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>(input);
        }

        public static T DeserializeJsonWithLoad<T>(string url) {
            return DeserializeJson<T>(Load(url));
        }
    }
}
