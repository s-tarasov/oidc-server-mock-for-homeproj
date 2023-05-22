using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
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

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                LoginPath = new PathString("/Account/Login"),
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
                ClientId = "code-id-token-mock-client",
                ClientSecret = "code-id-token-mock-secret",
                RedirectUri = "http://localhost:3000/callback",
                PostLogoutRedirectUri = "http://localhost:3000/",
                RedeemCode = true,
                SaveTokens =  true,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                RequireHttpsMetadata = false,
                Scope = "openid offline_access",
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    TokenResponseReceived = async t =>
                    {
                        var x = t;

                    }
                },


                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "name",

                },
                // More information on why the CookieManager needs to be set can be found here: 
                // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                CookieManager = new SameSiteCookieManager(new SystemWebCookieManager())
            });
        }
    }
}
