using System;
using System.Collections.Specialized;
using System.Linq;

namespace DotNetOpenAuth.Clients {
    public static class OAuthHelpers {
        public static string BuildUri(string url, string path, NameValueCollection query) {
            var uriBuilder = new UriBuilder(url) {
                Path = path,
                Query = ConstructQueryString(query)
            };
            return uriBuilder.ToString();
        }

        private static String ConstructQueryString(NameValueCollection parameters) {
            return String.Join("&", (from string name in parameters select String.Concat(name, "=", parameters[name])).ToArray());
        }
    }
}