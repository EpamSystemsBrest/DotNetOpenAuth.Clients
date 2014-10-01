using System;
using System.Web;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients {
    public class TwitterOAuthClient : IAuthenticationClient {

        #region IAuthenticationClient

        public string ProviderName { get { return "Twitter"; } }

        public void RequestAuthentication(HttpContextBase context, Uri returnUrl) {

            // пока все что вроде бы как работает это 
            // сигнатура остольное для меня загадка
            
            //var _target = new OAuthCreationService();

            //string url = "https://api.twitter.com/1/users/lookup.json";

            //string signature = _target.CreateSignature(url);
            
            
            
            
            
            throw new NotImplementedException();
        }

        public AuthenticationResult VerifyAuthentication(HttpContextBase context) {
            throw new NotImplementedException();
        }

        #endregion









    }

    public class OAuthCreationService
    {
        private readonly string _oathTimestamp;

        private readonly string _oauthNonce;
        private readonly TimeSpan _timeSpan;

        public OAuthCreationService()
        {
            _oauthNonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(
                DateTime.Now.Ticks.ToString()));
            _timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0);
            _oathTimestamp = Convert.ToInt64(_timeSpan.TotalSeconds).ToString();
        }

        public string OAuthTimeStamp
        {
            get { return _oathTimestamp; }
        }

        public string OauthSignatureMethod
        {
            get { return "HMAC-SHA1"; }
        }

        public string OauthConsumerKey
        {
            get { return "B8AbjInmTjtVptx7SR7t3tpPq"; }
        }

        public string OauthToken
        {
            get
            {
                return "2829540260-psKZdihcR8fqsW1ChFwVJ1rodeEu21AzQgUhhJK";
            }
        }

        public string OathVersion
        {
            get { return "1.0"; }
        }

        public string OAuthNonce
        {
            get { return _oauthNonce; }
        }


        public string CreateSignature(string url)
        {
            var dictionary = new SortedDictionary<string, string>
                                 {
                                     {"oauth_version", OathVersion},
                                     {"oauth_consumer_key", OauthConsumerKey},
                                     {"oauth_nonce", _oauthNonce},
                                     {"oauth_signature_method", OauthSignatureMethod},
                                     {"oauth_timestamp", _oathTimestamp},
                                     {"oauth_token", OauthToken}
                                 };
            var sb = new StringBuilder();
            sb.Append("POST&");
            sb.Append(Uri.EscapeDataString(url));
            sb.Append("&");
            foreach (var entry in dictionary)
            {
                sb.Append(Uri.EscapeDataString(string.Format("{0}={1}&", entry.Key, entry.Value)));
            }
            string baseString = sb.ToString().Substring(0, sb.Length - 3);

            string signingKey =
                Uri.EscapeDataString(OauthConsumerKey) + "&" +
                Uri.EscapeDataString(OauthToken);

            var hasher = new HMACSHA1(
                new ASCIIEncoding().GetBytes(signingKey));

            string signatureString = Convert.ToBase64String(
                hasher.ComputeHash(
                    new ASCIIEncoding().GetBytes(baseString)));

            return signatureString;
        }

        public string CreateAuthorizationHeaderParameter(string signature, string timeStamp)
        {
            string authorizationHeaderParams = String.Empty;
            authorizationHeaderParams += "OAuth ";
            authorizationHeaderParams += "oauth_consumer_key="
                                         + "\"" + Uri.EscapeDataString(OauthConsumerKey) + "\",";

            authorizationHeaderParams += "oauth_nonce=" + "\"" +
                                         Uri.EscapeDataString(OAuthNonce) + "\",";

            authorizationHeaderParams += "oauth_signature=" + "\""
                                         + Uri.EscapeDataString(signature) + "\",";

            authorizationHeaderParams +=
                "oauth_signature_method=" + "\"" +
                Uri.EscapeDataString(OauthSignatureMethod) +
                "\",";

            authorizationHeaderParams += "oauth_timestamp=" + "\"" +
                                         Uri.EscapeDataString(timeStamp) + "\",";

            authorizationHeaderParams += "oauth_token=" + "\"" +
                                         Uri.EscapeDataString(OauthToken) + "\",";

            authorizationHeaderParams += "oauth_version=" + "\"" +
                                         Uri.EscapeDataString(OathVersion) + "\"";
            return authorizationHeaderParams;
        }
    }















}
