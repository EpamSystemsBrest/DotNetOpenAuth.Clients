using System.Web.Mvc;
using System.Web.Security;
using Microsoft.Web.WebPages.OAuth;

namespace DotNetOpenAuth.Clients.Samples.Controllers {
    public class LoginController : Controller {
        [HttpGet]
        public ActionResult Index(string provider) {
            return Json(GetJsonObject(provider), JsonRequestBehavior.AllowGet);
        }

        private object GetJsonObject(string provider) {
            LoginWithProvider(provider);
            return new object();
        }

        public void LoginWithProvider(string provider) {
            OAuthWebSecurity.RequestAuthentication(provider, Url.Action("AuthenticationCallback"));
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