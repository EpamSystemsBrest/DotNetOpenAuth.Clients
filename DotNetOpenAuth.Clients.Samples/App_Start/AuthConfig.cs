using Microsoft.Web.WebPages.OAuth;

namespace DotNetOpenAuth.Clients.Samples {
    public class AuthConfig {
        public static void RegisterAuth() {
            // To let users of this site log in using their accounts from other sites such as Microsoft, Facebook, and Twitter,
            // you must update this site. For more information visit http://go.microsoft.com/fwlink/?LinkID=252166

            //OAuthWebSecurity.RegisterMicrosoftClient(
            //    clientId: "",
            //    clientSecret: "");

            //OAuthWebSecurity.RegisterTwitterClient(
            //    consumerKey: "",
            //    consumerSecret: "");

            //OAuthWebSecurity.RegisterFacebookClient(
            //    appId: "",
            //    appSecret: "");

            //OAuthWebSecurity.RegisterGoogleClient();

            OAuthWebSecurity.RegisterClient(new FlickrOAuthClient("c2b9248adf2b3a90214a1c20fe1fdef6", "c1c66b0a7f1ca84d"));
            OAuthWebSecurity.RegisterClient(new GooglePlusOAuthClient());
            OAuthWebSecurity.RegisterClient(new PinterestOAuthClient());
            OAuthWebSecurity.RegisterClient(new TumblrOAuthClient());
            OAuthWebSecurity.RegisterClient(new TwitterOAuthClient());
            OAuthWebSecurity.RegisterClient(new VkOAuthClient("4559228", "pkzqWBIXivRKrN8esLTS"));
        }
    }
}