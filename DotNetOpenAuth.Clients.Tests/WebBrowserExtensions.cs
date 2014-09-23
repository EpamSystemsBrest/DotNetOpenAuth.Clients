using System;
using System.IO;
using System.Linq;
using System.Web;
using System.Windows.Forms;

namespace DotNetOpenAuth.Clients.Tests {
    public static class WebBrowserExtentions {
        public static void Wait(this WebBrowser webBrowser) {
            for (int i = 0; i <= 400; i++) {
                Application.DoEvents();
            }
            while (webBrowser.IsBusy || (webBrowser.ReadyState != WebBrowserReadyState.Complete)) {
                Application.DoEvents();
            }
            for (int i = 0; i <= 400; i++) {
                Application.DoEvents();
            }
        }

        public static HtmlElement GetElementByTagAndAttribute(this WebBrowser webBrowser, string tagName, string attrName, string attrValue) {
            HtmlElement result = null;
            Try3Times(() => result = webBrowser.UnsafeGetElementByTagAndAttribute(tagName, attrName, attrValue),
                        webBrowser.LogBrowserHtml);

            return result;
        }

        public static HtmlElement UnsafeGetElementByTagAndAttribute(this WebBrowser webBrowser, string tagName, string attrName, string attrValue) {
            var result = webBrowser.Document.GetElementsByTagName(tagName)
                                            .Cast<HtmlElement>()
                                            .FirstOrDefault(x => x.GetAttribute(attrName).Equals(attrValue, StringComparison.InvariantCultureIgnoreCase));
            if (result == null)
                throw new Exception(string.Format("Element '{0}' with '{1}'='{2}' not found at page {3}",
                                                    tagName, attrName, attrValue, webBrowser.Url.AbsoluteUri));
            return result;
        }

        public static HtmlElement GetElementByTagAndAttributePart(this WebBrowser webBrowser, string tagName, string attrName, string partialName) {
            HtmlElement result = null;
            Try3Times(() => result = webBrowser.UnsafeGetElementByTagAndAttributePart(tagName, attrName, partialName),
                        webBrowser.LogBrowserHtml);

            return result;
        }

        private static HtmlElement UnsafeGetElementByTagAndAttributePart(this WebBrowser webBrowser, string tagName, string attrName, string partialName) {
            var result = webBrowser.Document.GetElementsByTagName(tagName)
                                            .Cast<HtmlElement>()
                                            .FirstOrDefault(x => x.GetAttribute(attrName).Contains(partialName));
            if (result == null)
                throw new Exception(string.Format("Element '{0}' with '{1}'='{2}' not found at page {3}",
                                                    tagName, attrName, partialName, webBrowser.Url.AbsoluteUri));
            return result;
        }

        public static HtmlElement GetElementByIdAndAttribute(this WebBrowser webBrowser, string id) {
            HtmlElement result = null;
            Try3Times(() => result = webBrowser.UnsafeGetElementByIdAndAttribute(id),
                        webBrowser.LogBrowserHtml);

            return result;
        }

        private static HtmlElement UnsafeGetElementByIdAndAttribute(this WebBrowser webBrowser, string id) {
            var result = webBrowser.Document.GetElementById(id);
            if (result == null)
                throw new Exception(string.Format("Element {0} not found at page {1}",
                                                    id, webBrowser.Url.AbsoluteUri));
            return result;
        }

        public static HttpRequestBase CreateRequestBase(this WebBrowser webBrowser) {
            var request = new HttpRequest(null, webBrowser.Url.AbsoluteUri, webBrowser.Url.Query.TrimStart('?'));
            var result = new HttpRequestWrapper(request);
            return result;
        }

        public static void Try3Times(Action tryAction, Action logAction) {
            for (int i = 0; i < 3; i++) {
                try {
                    tryAction();
                    break;
                } catch (Exception ex) {
                    Console.Write(ex.ToString());
                    logAction();
                }
            }
        }

        public static void LogBrowserHtml(this WebBrowser webBrowser) {
            var doc = webBrowser.Document;
            if (doc != null) {
                var currentUrl = string.Format("URL : {0}", doc.Url);
            }
            if (webBrowser.DocumentStream != null) {
                using (var reader = new StreamReader(webBrowser.DocumentStream)) {
                    var currentHtml = reader.ReadToEnd();
                }
            }
            webBrowser.Wait();
        }
    }
}
