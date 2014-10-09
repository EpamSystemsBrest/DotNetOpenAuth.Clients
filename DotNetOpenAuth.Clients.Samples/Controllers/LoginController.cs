using System.Web.Mvc;
using System.Web.Security;
using Microsoft.Web.WebPages.OAuth;

namespace DotNetOpenAuth.Clients.Samples.Controllers {
    public class LoginController : Controller {
        [HttpGet]
        public ActionResult Index(string provider) {
            OAuthWebSecurity.RequestAuthentication(provider, Url.Action("AuthenticationCallback"));
            return null;
        }

        [HttpGet]
        public ActionResult AuthenticationCallback() {
            GooglePlusOAuthClient.RewriteRequest(); // HACK for Google Plus
            var result = OAuthWebSecurity.VerifyAuthentication();
            if (!result.IsSuccessful) return View("Error", result.Error);

            var provider = result.Provider;
            var uniqueUserId = result.ProviderUserId;
            var uniqueId = provider + "/" + uniqueUserId;
            FormsAuthentication.SetAuthCookie(uniqueId, false);

            return View("LoggedIn", result);
        }
    }
}