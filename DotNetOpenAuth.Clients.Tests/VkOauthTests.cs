using System;
using System.Diagnostics;
using System.IO;
using System.Web;
using System.Windows.Forms;
using Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotNetOpenAuth.Clients.Tests {
    [TestClass]
    public class VkOAuthTests {
        private const string AppId = "4559228";
        private const string AppSecret = "pkzqWBIXivRKrN8esLTS";
        private const string OauthString = "https://oauth.vk.com/authorize?client_id=" + AppId + "&response_type=code&redirect_uri=localhost%2Fservices.aspx&display=popup&scope=friends";
        private const string ResponseString = "http://localhost/services.aspx?code=";

        private static readonly VkOAuthClient VkOAuthClient = new VkOAuthClient(AppId, AppSecret);

        [TestMethod]
        public void VerifyAuthentication() {
            var urlResult = GetUrlResult("demn_@tut.by", "Поменяла!");
            Assert.IsTrue(urlResult.Contains(ResponseString));
        }

        [TestMethod]
        public void VerifyWrongAuthentication() {
            var urlResult = GetUrlResult("demn_@tut.by", "Wrong!");
            Assert.IsFalse(urlResult.Contains(ResponseString));
        }

        //var httpContext =
        //          new HttpContext(new HttpRequest(string.Empty, "http://localhost:4545/login", string.Empty),
        //          new HttpResponse(new StringWriter()));
        //HttpContextBase httpContextBase = new HttpContextWrapper(httpContext);
        //VkOAuthClient.RequestAuthentication(httpContextBase, new Uri("http://localhost:4545/login"));
        //var q = VkOAuthClient.VerifyAuthentication(httpContextBase);
        //var name = q.UserName;


        private string GetUrlResult(string email, string pass) {
            using (var webBrowser = new WebBrowser { ScriptErrorsSuppressed = true }) {
                WaitingNavigationTo(webBrowser, OauthString);
                TryPassLoginPassPage(webBrowser, email, pass);
                TryPassingPermissionPage(webBrowser);
                return webBrowser.Url.AbsoluteUri;
            }
        }

        private static void WaitingNavigationTo(WebBrowser webBrowser, string oauthString) {
            webBrowser.Navigate(oauthString);
            webBrowser.Wait();
        }

        private void TryPassLoginPassPage(WebBrowser webBrowser, string email, string pass) {
            WebBrowserExtensions.Try3Times(() => PassLoginPage(webBrowser, email, pass),
                () => Debug.WriteLine(webBrowser.DocumentText));
            webBrowser.Wait();
        }

        private void TryPassingPermissionPage(WebBrowser webBrowser) {
            WebBrowserExtensions.Try3Times(() => PassPermissionPage(webBrowser),
                () => Debug.WriteLine(webBrowser.DocumentText));
            webBrowser.Wait();
        }

        private void PassPermissionPage(WebBrowser webBrowser) {
            var yesButton = webBrowser.GetElementByIdAndAttribute("install_allow");
            yesButton.InvokeMember("click");
            webBrowser.Wait();
        }

        private void PassLoginPage(WebBrowser webBrowser, string login, string pass) {
            var loginBox = webBrowser.GetElementByTagAndAttribute("input", "name", "email");

            if (loginBox == null) {
                var logout = webBrowser.GetElementByTagAndAttributePart("a", "href", "/logout");
                logout.InvokeMember("click");

                loginBox = webBrowser.GetElementByTagAndAttribute("input", "name", "email");
            }

            var passwordBox = webBrowser.GetElementByTagAndAttribute("input", "name", "pass");
            var submitButton = webBrowser.GetElementByIdAndAttribute("install_allow");

            loginBox.SetAttribute("value", login);
            passwordBox.SetAttribute("value", pass);
            submitButton.InvokeMember("click");

            webBrowser.Wait();
        }
    }
}
