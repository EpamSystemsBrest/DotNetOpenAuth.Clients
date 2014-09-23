using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotNetOpenAuth.Clients.Tests {
    [TestClass]
    public class VkOauthTests {
        private const string OauthString = "https://oauth.vk.com/authorize?client_id=4559228&response_type=code&redirect_uri=localhost%2Fservices.aspx&display=popup&scope=friends";
        private const string ResponseString = "http://localhost/services.aspx?code=";

        [TestMethod]
        public void VerifyAuthentication() {
            string urlResult = GetUrlResult("demn_@tut.by", "Поменяла!");
            Assert.IsTrue(urlResult.Contains(ResponseString));
        }

        [TestMethod]
        public void VerifyWrongAuthentication() {
            string urlResult = GetUrlResult("demn_@tut.by", "Wrong!");
            Assert.IsFalse(urlResult.Contains(ResponseString));
        }

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
