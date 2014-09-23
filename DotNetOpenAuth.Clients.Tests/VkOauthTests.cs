using System;
using System.Diagnostics;
using System.IO;
using System.Web;
using System.Windows.Forms;
using Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotNetOpenAuth.Clients.Tests {
    [TestClass]
    public class VkOauthTests {
        [TestMethod]
        public void VerifyAuthentication() {
            //Arrange
            string urlResult;
            using (var webBrowser = new WebBrowser { ScriptErrorsSuppressed = true, }) {
                webBrowser.Navigate("https://oauth.vk.com/authorize?client_id=4559228&response_type=code&redirect_uri=localhost%2Fservices.aspx&display=popup&scope=friends");
                webBrowser.Wait();
                WebBrowserExtentions.Try3Times(() => {
                    PassLoginPage(webBrowser, "login", "password");
                }, () => {
                    Debug.WriteLine(webBrowser.DocumentText);
                });
                webBrowser.Wait();

                WebBrowserExtentions.Try3Times(() => {
                    PassPermissionPage(webBrowser);
                }, () => {
                    Debug.WriteLine(webBrowser.DocumentText);
                });
                webBrowser.Wait();

                var requestBase = webBrowser.CreateRequestBase();
                urlResult = webBrowser.Url.AbsoluteUri;
                webBrowser.Dispose();
            }
            //Act

            //Assert
            Assert.IsFalse(urlResult.Contains("http://localhost/services.aspx?code="));
        }

        [TestMethod]
        public void VerifyWrongAuthentication() {
            //Arrange
            string urlResult;
            using (var webBrowser = new WebBrowser { ScriptErrorsSuppressed = true, }) {
                webBrowser.Navigate("https://oauth.vk.com/authorize?client_id=4559228&response_type=code&redirect_uri=localhost%2Fservices.aspx&display=popup&scope=friends");
                webBrowser.Wait();
                WebBrowserExtentions.Try3Times(() => {
                    PassLoginPage(webBrowser, "wrong_login", "wrong_password");
                }, () => {
                    Debug.WriteLine(webBrowser.DocumentText);
                });
                webBrowser.Wait();

                WebBrowserExtentions.Try3Times(() => {
                    PassPermissionPage(webBrowser);
                }, () => {
                    Debug.WriteLine(webBrowser.DocumentText);
                });
                webBrowser.Wait();

                var requestBase = webBrowser.CreateRequestBase();
                urlResult = webBrowser.Url.AbsoluteUri;
                webBrowser.Dispose();
            }
            //Act

            //Assert
            Assert.IsTrue(urlResult.Contains("http://localhost/services.aspx?code="));
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
