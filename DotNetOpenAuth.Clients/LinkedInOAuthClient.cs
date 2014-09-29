using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class LinkedInOAuthClient : IAuthenticationClient {
        private const string OAuthUrl = "https://www.linkedin.com/";
        private const string ApiUrl = "https://api.linkedin.com/";

        private readonly string _appKey;
        private readonly string _appSecret;

        public LinkedInOAuthClient(string apiKey, string secretKey) {
            _appKey = apiKey;
            _appSecret = secretKey;
        }

        #region IAuthenticationClient

        public string ProviderName { get { return "LinkedIn"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {
            var uri = OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/authorization", new NameValueCollection() {
                                { "response_type", "code"},
                                { "client_id",     _appKey },
                                { "state",         Guid.NewGuid().ToString("N")   },
                                { "redirect_uri" , HttpUtility.UrlEncode(returnUrl.AbsoluteUri) }
            });
            try {
                context.Response.Redirect(uri);
            } catch { //Tests context //TODO: @demns
                context.Response.RedirectLocation = uri;
            }
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            var accessToken = GetAccessToken(context);
            var userData = GetUserData(accessToken);

            // /~?oauth2_access_token=AQXdSP_W41_UPs5ioT_t8HESyODB4FqbkJ8LrV_5mff4gPODzOYR
            //http://localhost:56194/Login/AuthenticationCallback?__provider__=LinkedIn&
            //code=AQRgYx4DNtYYl4KVk42AKuYzNdbdRwcctP_aDvuctkeO-rFJRKCpQz7-gexamgqf3-TiL0STi9eyqdCUbAJ0sX0pTNhGUDxIQ7r8AI6a59oAr8BXH5A
            //&state=d2908de77094451b922422e62351906d
            try {
                return new AuthenticationResult(
                    isSuccessful: true,
                    provider: ProviderName,
                    providerUserId: userData.headline,
                    userName: userData.firstName + userData.lastName + "link",
                    extraData:
                        new Dictionary<string, string>());
            } catch (WebException ex) {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            } catch (Exception ex) {
                return new AuthenticationResult(ex);
            }
        }

        #endregion

        private AccessToken GetAccessToken(HttpContextBase context) {
            var code = context.Request["code"];
            //https://www.linkedin.com/uas/oauth2/accessToken?grant_type=authorization_code
            //                           &code=AUTHORIZATION_CODE
            //                           &redirect_uri=YOUR_REDIRECT_URI
            //                           &client_id=YOUR_API_KEY
            //                           &client_secret=YOUR_SECRET_KEY
            var address = OAuthHelpers.BuildUri(OAuthUrl, "uas/oauth2/accessToken", new NameValueCollection()
            {
                {"grant_type", "authorization_code"},
                {"code", code},
                {"redirect_uri", HttpUtility.UrlEncode(RemoveUriParameter(context.Request.Url, "state", "code"))},
                {"client_id", _appKey},
                {"client_secret", _appSecret}
            });

            //try {
            //    var q = Load(address);
            //} catch (WebException ex) {
            //    var responseStream = (MemoryStream)ex.Response.GetResponseStream();
            //    throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            //}

            //throw new NotImplementedException();
            //return DeserializeJson<AccessToken>(Load(address));
            return DeserializeJson<AccessToken>(Load(address));
        }

        private static UserData GetUserData(AccessToken accessToken) {
            var address = OAuthHelpers.BuildUri(ApiUrl, "v1/people/~", new NameValueCollection()
            {
                {"oauth2_access_token", accessToken.access_token},
                {"format", "json"}
            });

            try {
                return DeserializeJson<UserData>(Load(address));
            } catch (WebException ex) {
                var responseStream = (MemoryStream)ex.Response.GetResponseStream();
                throw new Exception(Encoding.UTF8.GetString(responseStream.ToArray()));
            }
        }

        private static string RemoveUriParameter(Uri uri, params string[] uriParameterName) {
            var valueCollection = HttpUtility.ParseQueryString(uri.Query);

            foreach (var str in uriParameterName) {
                if (!string.IsNullOrEmpty(valueCollection[str]))
                    valueCollection.Remove(str);
            }

            if (valueCollection.HasKeys())
                return uri.GetLeftPart(UriPartial.Path) + "?" + valueCollection;
            return uri.GetLeftPart(UriPartial.Path);
        }

        private static string Load(string address) {
            var request = WebRequest.Create(address) as HttpWebRequest;
            using (var response = request.GetResponse() as HttpWebResponse) {
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    return reader.ReadToEnd();
                }
            }
        }

        private static T DeserializeJson<T>(string input) {
            var serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>(input);
        }

        private class AccessToken {
            public string access_token = null;
            public string expires_in = null;
        }

        private class UserData {
            public string firstName = null;
            public string headline = null;
            public string lastName = null;
        }

        //{
        //  "firstName": "Dmitry",
        //  "headline": " ",
        //  "lastName": "Samsonov",
        //  "siteStandardProfileRequest": {"url": "https://www.linkedin.com/profile/view?id=195427531&authType=name&authToken=wD_m&trk=api*a3504273*s3575593*"}
        //}
    }
}
