using System;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class PinterestOAuthClient : IAuthenticationClient {
        public PinterestOAuthClient(string appId, string appSecret) {
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "Pinterest"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            throw new NotImplementedException();
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            throw new NotImplementedException();
        }

        #endregion
    }
}
