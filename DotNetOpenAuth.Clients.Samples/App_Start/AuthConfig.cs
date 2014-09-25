﻿using Clients;
using Microsoft.Web.WebPages.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

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

            OAuthWebSecurity.RegisterClient(new VkOAuthClient("4559228", "pkzqWBIXivRKrN8esLTS"));
            OAuthWebSecurity.RegisterClient(new FlickrOAuthClient("c2b9248adf2b3a90214a1c20fe1fdef6", "c1c66b0a7f1ca84d"));
        }
    }
}