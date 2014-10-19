using System;
using System.Collections.Specialized;
using System.Web;

namespace DotNetOpenAuth.Clients {
    public static class AuthClient {
        public static string CreateRedirectionUri(string url, string path, string appId, Uri returnUrl) {
            return OAuthHelpers.BuildUri(url, path, new NameValueCollection {
                { "client_id",      appId },
                { "redirect_uri",   HttpUtility.UrlEncode(returnUrl.AbsoluteUri) },
                { "response_type",  "code" },
            });
        }
    }
}