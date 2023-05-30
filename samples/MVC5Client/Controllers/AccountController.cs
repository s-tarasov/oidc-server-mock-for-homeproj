using System;
using System.Web;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security;
using System.Web.Mvc;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using MVC5Client.Misc;
using Microsoft.Owin;
using System.Globalization;
using System.Security.Claims;
using System.Collections.Generic;

namespace MVC5Client.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login(string returnUrl)
        {
            var manager = new SameSiteCookieManager(new Microsoft.Owin.Security.Interop.ChunkingCookieManager());
            manager.DeleteCookie(Request.GetOwinContext(), CookieAuthenticationDefaults.CookiePrefix + CookieAuthenticationDefaults.AuthenticationType,
                new CookieOptions());

            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? Url.Action("Index", "Home")
            }, "OIDC");

            return new HttpUnauthorizedResult();
        }

        public async Task<ActionResult> Refresh(string returnUrl)
        {
            var ticket = await Request.GetOwinContext().Authentication
                 .AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);


            var tokenInvoker = Request.GetOwinContext().Get<IRefreshTokenInvoker>(nameof(IRefreshTokenInvoker));
            try
            {
                var freshTokensResult = await tokenInvoker.GetTokensAsync(ticket.Properties.Dictionary[OpenIdConnectParameterNames.RefreshToken]);
                ticket.Properties.Dictionary[OpenIdConnectParameterNames.RefreshToken] = freshTokensResult.RefreshToken;
                ticket.Properties.Dictionary[OpenIdConnectParameterNames.AccessToken] = freshTokensResult.AccessToken;
                ticket.Properties.Dictionary[OpenIdConnectParameterNames.IdToken] = freshTokensResult.IdToken;

                if (!string.IsNullOrEmpty(freshTokensResult.ExpiresIn)
                    && int.TryParse(freshTokensResult.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(value);
                    ticket.Properties.Dictionary["expires_at"] = expiresAt.ToString("o", CultureInfo.InvariantCulture);
                }

                HttpContext.GetOwinContext().Authentication.SignIn(ticket.Properties, ticket.Identity);

                return Redirect(returnUrl);

            }
            catch (Exception exception)
            {
                
            }

            // TODO не работает, разобраться или почистить через куки CookieManager
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);

            var props = new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? Url.Action("Index", "Home"),

            };
            props.Dictionary["prompt"] = "none";
            HttpContext.GetOwinContext().Authentication.Challenge(props, "OIDC");
            return new HttpUnauthorizedResult();
        }

        public async Task Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            HttpContext.GetOwinContext().Authentication.SignOut(new AuthenticationProperties
            {
                RedirectUri = "http://multidomainapp.local:3000/logoutcallback/"
            }, "OIDC");
        }

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

        
        public async Task<ActionResult> SubdomainCallback(string redirectUri)
        {
            var result = await HttpContext.GetOwinContext().Authentication.AuthenticateAsync("Temporary");

            HttpContext.GetOwinContext().Authentication.SignIn(
                result.Properties,
                new ClaimsIdentity(result.Identity.Claims, CookieAuthenticationDefaults.AuthenticationType));
            HttpContext.GetOwinContext().Authentication.SignOut("Temporary");

            return Redirect(redirectUri);
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }

        [Authorize]
        public async Task<ActionResult> Properties()
        {
            var result = await Request.GetOwinContext().Authentication
               .AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
            return View(result.Properties.Dictionary);
        }

        public ActionResult IsAuthorized()
        {
            return this.Json(User.Identity.IsAuthenticated, JsonRequestBehavior.AllowGet);
        }
    }
}
