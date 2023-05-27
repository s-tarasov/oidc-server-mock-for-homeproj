using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Policy;
using System.Web;
using Microsoft.Owin.Security.Cookies;
using System.Web.Mvc;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace MVC5Client.Controllers
{
    public class AccountController : Controller
    {

        [Authorize]
        public async Task<ActionResult> Tokens()
        {
            var result = await Request.GetOwinContext().Authentication
                .AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);

            ViewBag.RefreshToken = result.Properties.Dictionary[OpenIdConnectParameterNames.RefreshToken];
            ViewBag.AccessToken = result.Properties.Dictionary[OpenIdConnectParameterNames.AccessToken];
            ViewBag.IdToken = result.Properties.Dictionary[OpenIdConnectParameterNames.IdToken];

            return View();
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }

        public ActionResult IsAuthorized()
        {
            return this.Json(User.Identity.IsAuthenticated, JsonRequestBehavior.AllowGet);
        }
    }
}
