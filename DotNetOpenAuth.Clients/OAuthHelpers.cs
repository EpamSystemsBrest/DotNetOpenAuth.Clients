using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
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

        public static string Load(string address) { //TODO: check for webclient (currently doesn't work with russian culture)
            var request = WebRequest.Create(address);
            using (var response = request.GetResponse()) {
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    return reader.ReadToEnd();
                }
            }
        }

        public static string PostRequest(string postUrl, string path, NameValueCollection param) {
            using (var wb = new WebClient()) {
                var url = (new UriBuilder(postUrl) { Path = path }.ToString());
                return Encoding.UTF8.GetString(wb.UploadValues(url, "POST", param));
            }
        }

        public static T DeserializeJson<T>(string input) {
            var serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>(input);
        }

        public static T DeserializeJsonWithLoad<T>(string url) {
            return DeserializeJson<T>(Load(url));
        }

        public static string GetValueFromRequest(string request, string value)
        {
            return HttpUtility.ParseQueryString(request).Get(value);
        }
    }
}
