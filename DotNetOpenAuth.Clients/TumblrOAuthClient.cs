using System;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace Clients {
    public class TumblrOAuthClient : IAuthenticationClient {
        #region IAuthenticationClient

        public string ProviderName { get { return "Tumblr"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            throw new NotImplementedException();
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            throw new NotImplementedException();
        }

        #endregion
    }
}
