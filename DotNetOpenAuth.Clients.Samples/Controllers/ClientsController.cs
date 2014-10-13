using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using DotNetOpenAuth.AspNet;

namespace DotNetOpenAuth.Clients.Samples.Controllers
{
    public class ClientsController : Controller
    {
        // GET: Clients
        public PartialViewResult Index()
        {
            var z = FindDerivedTypesFrom("DotNetOpenAuth.Clients");
            return PartialView(z);
        }

        public IEnumerable<string> FindDerivedTypesFrom(string assemblyName)
        { //TODO: check and replace
            return AppDomain.CurrentDomain.GetAssemblies().
                             SingleOrDefault(a => a.GetName().Name == assemblyName).GetTypes().
                             Where(t => t.GetInterfaces().Contains(typeof(IAuthenticationClient))).
                             Select(t => t.FullName.Replace("DotNetOpenAuth.Clients.", "").Replace("OAuthClient", "").ToLower());

            //TODO: chat with someone about 401 (wrong signature) (only in signature-based clients) with the code below
            //Select(t => Activator.CreateInstance(t, "", "") as IAuthenticationClient).
            //Select(instance => instance.ProviderName);
        }
    }
}