using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web;
using System.Windows.Forms;
using Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotNetOpenAuth.Clients.Tests {
    [TestClass]
    public class VkOauthTests {
        private const string Url = "http://aaa.vcap.me";
        private const string ResponseString = "Дмитрий Самсонов";
        private static readonly VkOAuthClient VkOAuthClient = new VkOAuthClient("4559228", "pkzqWBIXivRKrN8esLTS");

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

        private string GetUrlResult(string email, string pass) {
            using (var webBrowser = new WebBrowser { ScriptErrorsSuppressed = true }) {
                var httpContext =
                    new HttpContext(new HttpRequest(string.Empty, Url, string.Empty),
                        new HttpResponse(new StringWriter(new StringBuilder())));
                HttpContextBase httpContextBase = new HttpContextWrapper(httpContext);

                VkOAuthClient.RequestAuthentication(httpContextBase, new Uri(Url));
                WaitingNavigationTo(webBrowser, httpContext.Response.RedirectLocation);
                TryPassLoginPassPage(webBrowser, email, pass);
                TryPassingPermissionPage(webBrowser);

                httpContext =
                    new HttpContext(new HttpRequest(string.Empty, Url, webBrowser.Url.Query.TrimStart('?')),
                        new HttpResponse(new StringWriter(new StringBuilder())));
                httpContextBase = new HttpContextWrapper(httpContext);

                return VkOAuthClient.VerifyAuthentication(httpContextBase).UserName;
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
