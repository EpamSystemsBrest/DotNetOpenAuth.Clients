using DotNetOpenAuth.AspNet.Clients;
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
            OAuthWebSecurity.RegisterClient(new GooglePlusOAuthClient("1067161712157-p1969b3q6q18v0c2anp97iarthtrmis2.apps.googleusercontent.com", "VE2aut2r8nKrmoYGGjLyrilt"));
            OAuthWebSecurity.RegisterClient(new PinterestOAuthClient());
            OAuthWebSecurity.RegisterClient(new TumblrOAuthClient("fq4O66FfwrEoXISW8xKaeGh8LOQYBHV8IBH9pPTkRPbxv8GW0M", "baHrYQazVReM0CDomuTljbo5yNA8ZvAejxovMLiMoak78AF0jk"));
            OAuthWebSecurity.RegisterClient(new TwitterOAuthClient());
            OAuthWebSecurity.RegisterClient(new VkOAuthClient("4559228", "pkzqWBIXivRKrN8esLTS"));
            OAuthWebSecurity.RegisterClient(new LinkedInOAuthClient("77dcvkuxzrne0a", "3jNO4YRQxWj8Xx3B"));
            OAuthWebSecurity.RegisterClient(new InstagramOAuthClient("36342c21bc7b4a8a8ea50669d39549c8", "f2440fc49e5c49959e27fbe3410d70a5"));
            OAuthWebSecurity.RegisterClient(new FacebookOAuthClient("637656729683033", "22d9e594cbe5c77a54fbd3507ab9c879"));
        }
    }
}