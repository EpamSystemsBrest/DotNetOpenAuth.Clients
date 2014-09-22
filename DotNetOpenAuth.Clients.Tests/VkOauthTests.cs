using System.Windows.Forms;
using Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotNetOpenAuth.Clients.Tests {
    [TestClass]
    public class VkOauthTests {
        [TestMethod]
        public void VerifyAuthentication() {
            //Arrange
            //https://oauth.vk.com/authorize?client_id=4559228&response_type=code&redirect_uri=localhost%2Fservices.aspx&display=popup&scope=friends

            //<div class="form_header">Phone or email</div>
            //<input class="form_input" type="text" value="" name="email">
            //<div class="form_header">Password</div>
            //<input class="form_input" type="password" name="pass">
            //<div class="popup_login_btn">
            //<button id="install_allow" class="flat_button popup_login_btn button_big" onclick="return login();" type="submit">Log in</button>
            //</div>

            using (var webBrowser = new WebBrowser { ScriptErrorsSuppressed = true }) {
                //webBrowser.Navigate(loginUri.AbsoluteUri);
                //webBrowser.Wait();
            }

            var vk = new VkOAuthClient("4559228", "pkzqWBIXivRKrN8esLTS");

            //Act



            //Assert

        }
    }
}
