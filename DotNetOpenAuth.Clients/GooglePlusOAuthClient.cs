using System;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace Clients {
    public class GooglePlusOAuthClient : IAuthenticationClient {

        #region IAuthenticationClient

        public string ProviderName { get { return "Google"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            throw new NotImplementedException();
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            throw new NotImplementedException();
        }

        #endregion
    }
}
