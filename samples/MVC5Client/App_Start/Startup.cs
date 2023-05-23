using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using MVC5Client.Misc;
using Owin;
using static System.Net.WebRequestMethods;

[assembly: OwinStartup(typeof(MVC5Client.Startup))]

namespace MVC5Client
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ILogger logger = app.CreateLogger<Startup>();
            logger.WriteError("App is starting up");

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                LoginPath = new PathString("/Account/Login"),
                CookieDomain = ".multidomainapp.local",
                CookieSameSite = SameSiteMode.Lax,
                // More information on why the CookieManager needs to be set can be found here: 
                // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                CookieManager = new SameSiteCookieManager(new SystemWebCookieManager())
            });
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "OIDC",
                Authority = "http://localhost:51990",
                ClientId = "multidomainapp",
                ClientSecret = "multidomainapp-secret",
                RedirectUri = "http://multidomainapp.local:3000/callback",
                PostLogoutRedirectUri = "http://multidomainapp.local:3000/",
                RedeemCode = true,
                SaveTokens =  true,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                RequireHttpsMetadata = false,
                Scope = "openid offline_access",
                Notifications = new OpenIdConnectAuthenticationNotifications {

                    SecurityTokenValidated = async n =>
                    {
                        n.AuthenticationTicket.Properties.Dictionary["region"] = "spb";
                    /*    var redirectUri = new Uri(n.AuthenticationTicket.Properties.RedirectUri);
                        n.AuthenticationTicket.Properties.RedirectUri
                        = "http://spb.multidomainapp.local:3000/Account/CopyCookie?redirectUri="
                        + Uri.EscapeDataString(redirectUri.PathAndQuery);
                    */
                        var uriBuilder = new UriBuilder(n.AuthenticationTicket.Properties.RedirectUri);
                        uriBuilder.Host = "spb.multidomainapp.local";
                        n.AuthenticationTicket.Properties.RedirectUri = uriBuilder.ToString();

                        n.AuthenticationTicket.Identity.AddClaim(new Claim("regionName", "Питер"));
                    }
                },
                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "name",

                },
                // More information on why the CookieManager needs to be set can be found here: 
                // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                CookieManager = new RootDomainCookieManger(new SameSiteCookieManager(new SystemWebCookieManager()))
            });
        }
    }
}
