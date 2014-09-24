using DotNetOpenAuth.AspNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace Clients
{
    public class FlickrOAuthClient : IAuthenticationClient
    {
        private const string OAuthUrl = "http://www.flickr.com/services/oauth//request_token";
        private const string ApiUrl = "http://api.flickr.com";
        private string _appId;
        private string _appSecret;
        private string signature;
        public string ProviderName { get; private set; }

        public FlickrOAuthClient(string appId, string appSecret)
        {
            _appId = appId;
            _appSecret = appSecret;
            ProviderName = "Flickr";
        }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            //generate a random nonce and a timestamp
            var rand = new Random();
            var nonce = rand.Next(999999).ToString();
            var timestamp = GetTimestamp();

            //create the parameter string in alphabetical order
            var parameters = "oauth_callback=" + UrlHelper.Encode(returnUrl.AbsoluteUri)
                                + "&oauth_consumer_key=" + _appId
                                + "&oauth_nonce=" + nonce
                                + "&oauth_signature_method=HMAC-SHA1"
                                + "&oauth_timestamp=" + timestamp
                                + "&oauth_version=1.0";

            //generate a signature base on the current requeststring and parameters
            signature = GenerateSignature("GET", OAuthUrl, parameters);

            //add the parameters and signature to the requeststring
            var url = OAuthUrl + "?" + parameters + "&oauth_signature=" + signature;

            //get request string
            var client = new WebClient();
            var request = client.DownloadString(url);
            var requestToken = request.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries)[1];
            var flickr_oauth = "http://www.flickr.com/services/oauth/authorize";
            var answer = flickr_oauth + "?" + requestToken;

            //redirect
            HttpContext.Current.Response.Redirect(answer, false);
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context)
        {
            //var oauth_verifier = context.Request.QueryString["oauth_verifier"];
            //var oauth_token = context.Request.QueryString["oauth_token"];
            //var flickr_access_token = "http://www.flickr.com/services/oauth/access_token";
            //var parameters =
            //            "?oauth_consumer_key=" + _appId +
            //            "&oauth_nonce=37026218" +
            //            "&oauth_signature_method=HMAC-SHA1" +
            //            "&oauth_timestamp=1305586309" +
            //            "&oauth_token=" +oauth_token+
            //            "&oauth_verifier=" +oauth_verifier+
            //            "&oauth_version=1.0";
            //var sig = GenerateSignature("GET", flickr_access_token, parameters);
            //var client = new WebClient();
            //var url = flickr_access_token + parameters + "&oauth_signature=" + sig;
            //var request = client.DownloadString(url);

            throw new NotImplementedException();
        }

        private string GenerateSignature(string httpMethod, string ApiEndpoint, string parameters)
        {
            //url encode the API endpoint and the parameters       
            var encodedUrl = UrlHelper.Encode(ApiEndpoint);
            var encodedParameters = UrlHelper.Encode(parameters);

            //generate the basestring
            var basestring = httpMethod + "&" + encodedUrl + "&";
            parameters = UrlHelper.Encode(parameters);
            basestring = basestring + parameters;

            var encoding = new ASCIIEncoding();

            //create key (request_token can be an empty string)
            var key = _appSecret + "&";
            var keyByte = encoding.GetBytes(key);

            //create message to encrypt
            var messageBytes = encoding.GetBytes(basestring);
            string signature;
            //encrypt message using hmac-sha1 with the provided key
            using (var hmacsha1 = new HMACSHA1(keyByte))
            {
                byte[] hashmessage = hmacsha1.ComputeHash(messageBytes);
                signature = Convert.ToBase64String(hashmessage);
            }
            return UrlHelper.Encode(signature);
        }
        public static String GetTimestamp()
        {
            int epoch = (int)(DateTime.UtcNow - new DateTime(2000, 1, 1)).TotalSeconds;
            return epoch.ToString();
        }

    }
    /// <summary> 
    /// URL encoding class.  Note: use at your own risk. 
    /// Written by: Ian Hopkins (http://www.lucidhelix.com) 
    /// Date: 2008-Dec-23 
    /// (Ported to C# by t3rse (http://www.t3rse.com)) 
    /// </summary> 
    public class UrlHelper
    {
        public static string Encode(string str)
        {
            var charClass = String.Format("0-9a-zA-Z{0}", Regex.Escape("-_.!~*'()"));
            return Regex.Replace(str,
                String.Format("[^{0}]", charClass),
                new MatchEvaluator(EncodeEvaluator));
        }
        public static string EncodeEvaluator(Match match)
        {
            return (match.Value == " ") ? "+" : String.Format("%{0:X2}", Convert.ToInt32(match.Value[0]));
        }

    } 
}
