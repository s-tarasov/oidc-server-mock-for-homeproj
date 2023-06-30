using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Interop;
using MVC5Client.Misc;
using Owin;

[assembly: OwinStartup(typeof(MVC5Client.Startup))]

namespace MVC5Client
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ILogger logger = app.CreateLogger<Startup>();
            logger.WriteError("App is starting up");

            var ticketFormat = new AspNetTicketDataFormat(
        new DataProtectorShim(
            DataProtectionProvider.Create(new DirectoryInfo(@"c:\Temp\Rings"),
            builder => builder.SetApplicationName("SharedCookieApp").DisableAutomaticKeyGeneration())
            .CreateProtector(
                "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
                // Must match the Scheme name used in the ASP.NET Core app, i.e. IdentityConstants.ApplicationScheme
                "Cookies",
                "v2")));


            app.MapWhen(x => true, appM =>
                appM.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                    LoginPath = new PathString("/Account/Login"),
                    CookieSameSite = SameSiteMode.Lax,
                    // More information on why the CookieManager needs to be set can be found here: 
                    // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                    CookieManager = new SameSiteCookieManager(new /*SystemWeb*/ChunkingCookieManager()),
                    TicketDataFormat = ticketFormat,
                    Provider = new CookieAuthenticationProvider()
                    {
                        OnValidateIdentity = async ctx =>
                        {
                            var exp = DateTime.Parse(ctx.Properties.Dictionary["expires_at"]);
                            if (exp < DateTime.Now)
                                ctx.OwinContext.Authentication.Challenge(new AuthenticationProperties
                                {
                                    RedirectUri = "/Account/Refresh?returnUrl=" + Uri.UnescapeDataString(ctx.OwinContext.Request.Uri.ToString()),
                                }, CookieAuthenticationDefaults.AuthenticationType);
                        },
                        OnApplyRedirect = ctx =>
                        {
                            if (ctx.Request.Headers["X-Requested-With"] != "XMLHttpRequest" && ctx.Request.Method == "GET")
                            {
                                var relativeRedirectUri = new Uri(ctx.RedirectUri, UriKind.RelativeOrAbsolute).IsAbsoluteUri
                                    ? new Uri(ctx.RedirectUri).PathAndQuery
                                    : ctx.RedirectUri;
                                if (relativeRedirectUri.StartsWith("/passive/", StringComparison.InvariantCultureIgnoreCase))
                                    relativeRedirectUri = relativeRedirectUri.Substring("/passive".Length);
                                ctx.Response.Redirect(relativeRedirectUri);
                            }
                        }
                    }
                }));
        }
    }


}
