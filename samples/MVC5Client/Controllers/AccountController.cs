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
            var manager = new SameSiteCookieManager(new Microsoft.Owin.Security.Interop.ChunkingCookieManager());
            var ticketCookieValue = manager.GetRequestCookie(Request.GetOwinContext(), CookieAuthenticationDefaults.CookiePrefix + CookieAuthenticationDefaults.AuthenticationType);
            var ticket = Startup.TicketFormat.Unprotect(ticketCookieValue);

            
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
                var newTicketCookieValue = Startup.TicketFormat.Protect(ticket);

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.GetOwinContext().Request.IsSecure,
                    Expires = ticket.Properties.ExpiresUtc.Value.UtcDateTime
                };
                
                manager.AppendResponseCookie(Request.GetOwinContext(),
                    CookieAuthenticationDefaults.CookiePrefix + CookieAuthenticationDefaults.AuthenticationType,
                    newTicketCookieValue,
                    cookieOptions);

                return Redirect(returnUrl);

            }
            catch (Exception exception)
            {
                
            }
         
            manager.DeleteCookie(Request.GetOwinContext(), CookieAuthenticationDefaults.CookiePrefix + CookieAuthenticationDefaults.AuthenticationType,
                new CookieOptions());
            

            var props = new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? Url.Action("Index", "Home"),

            };
            props.Dictionary["prompt"] = "none";
            HttpContext.GetOwinContext().Authentication.Challenge(props, "OIDC");
            return new HttpUnauthorizedResult();
        }

        [Authorize]
        public void Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            HttpContext.GetOwinContext().Authentication.SignOut("OIDC");
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
            var manager = new SameSiteCookieManager(new Microsoft.Owin.Security.Interop.ChunkingCookieManager());
            var cookieValue = manager.GetRequestCookie(Request.GetOwinContext(), CookieAuthenticationDefaults.CookiePrefix + "Temporary");
            manager.AppendResponseCookie(Request.GetOwinContext(), ".AspNet.Cookies", cookieValue, new CookieOptions
            {
                Expires = DateTime.Now.AddDays(1),
                HttpOnly = true
            });

            manager.DeleteCookie(Request.GetOwinContext(), CookieAuthenticationDefaults.CookiePrefix + "Temporary", new CookieOptions
            {
                Domain = ".multidomainapp.local"
            });

            return Redirect(redirectUri);
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
