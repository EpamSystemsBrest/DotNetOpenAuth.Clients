using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DotNetOpenAuth.Clients {
    public class SignatureGenerator {
        private readonly string _appSecret;
        private readonly string _tokenSecret;

        public SignatureGenerator(string appSecret, string tokenSecret) {
            _appSecret = appSecret;
            _tokenSecret = tokenSecret;
        }

        public string GenerateSignature(string httpMethod, string apiEndpoint, string parameters, bool getToken = false) {
            var basestring = httpMethod + "&" + Encode(apiEndpoint) + "&" + Encode(parameters);

            var encoding = new ASCIIEncoding();

            var key = getToken ? _appSecret + "&" : _appSecret + "&" + _tokenSecret;
            var keyByte = encoding.GetBytes(key);

            var messageBytes = encoding.GetBytes(basestring);
            string signature;
            using (var hmacsha1 = new HMACSHA1(keyByte)) {
                byte[] hashmessage = hmacsha1.ComputeHash(messageBytes);
                signature = Convert.ToBase64String(hashmessage);
            }
            return Encode(signature);
        }

        public static string GetTimestamp() {
            return ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).
                ToString(CultureInfo.InvariantCulture);
        }

        public static string GenerateNonce() {
            return Guid.NewGuid().ToString();
        }

        public static string Encode(string str) {
            var charClass = String.Format("0-9a-zA-Z{0}", Regex.Escape("-_.!~*'()"));
            return Regex.Replace(str, String.Format("[^{0}]", charClass), EncodeEvaluator);
        }

        private static string EncodeEvaluator(Match match) {
            return (match.Value == " ") ? "+" : String.Format("%{0:X2}", Convert.ToInt32(match.Value[0]));
        }
    }
}