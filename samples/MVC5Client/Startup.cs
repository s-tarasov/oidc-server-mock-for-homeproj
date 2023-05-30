using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Interop;
using Microsoft.Owin.Security.OpenIdConnect;
using MVC5Client.Misc;
using Owin;

[assembly: OwinStartup(typeof(MVC5Client.Startup))]

namespace MVC5Client
{
    public class Startup
    {
        public static AspNetTicketDataFormat TicketFormat;

        public void Configuration(IAppBuilder app)
        {
            ILogger logger = app.CreateLogger<Startup>();
            logger.WriteError("App is starting up");

            TicketFormat = new AspNetTicketDataFormat(
      new DataProtectorShim(
          DataProtectionProvider.Create(new DirectoryInfo(@"c:\Temp\Rings"),
          builder => builder.SetApplicationName("SharedCookieApp"))
          .CreateProtector(
              "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
              CookieAuthenticationDefaults.AuthenticationType,
              "v2")));

            var authPaths = new[] { "/callback", "/Account/Login", "/Account/Refresh", "/Account/SubdomainCallback", "/Account/Logout" };
            app.MapWhen(c => authPaths.Contains(c.Request.Path.Value), appM =>
            {
                appM.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = "Temporary",
                    CookieName = CookieAuthenticationDefaults.CookiePrefix + "Temporary",
                    CookieDomain = ".multidomainapp.local",
                    TicketDataFormat = TicketFormat,
                    AuthenticationMode = AuthenticationMode.Passive,
                    CookieSameSite = SameSiteMode.Lax,
                    ExpireTimeSpan = TimeSpan.FromSeconds(30),
                    // More information on why the CookieManager needs to be set can be found here: 
                    // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                    CookieManager = new SameSiteCookieManager(new ChunkingCookieManager()),
                    Provider = new CookieAuthenticationProvider
                    {
                        OnResponseSignIn = ctx =>
                        {
                            ctx.Properties.IsPersistent = true;
                            ctx.Properties.ExpiresUtc = DateTime.UtcNow.AddDays(1);
                        }
                    }
                });

                appM.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                    LoginPath = new PathString("/Account/Login"),
                    CookieSameSite = SameSiteMode.Lax,
                    // More information on why the CookieManager needs to be set can be found here: 
                    // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                    CookieManager = new SameSiteCookieManager(new ChunkingCookieManager()),
                    TicketDataFormat = TicketFormat
                });

                appM.Use(typeof(CustomOpenIdConnectAuthenticationMiddleware), appM, new OpenIdConnectAuthenticationOptions
                {
                    AuthenticationType = "OIDC",
                    Authority = "http://localhost:51990",
                    ClientId = "multidomainapp",
                    ClientSecret = "multidomainapp-secret",
                    RedirectUri = "http://multidomainapp.local:3000/callback",
                    PostLogoutRedirectUri = "http://multidomainapp.local:3000/",
                    RedeemCode = true,
                    SaveTokens = true,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    RequireHttpsMetadata = false,
                    Scope = "openid offline_access",
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = async ctx =>
                        {
                            if (ctx.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                            {
                                var result = await ctx.OwinContext.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
                                ctx.ProtocolMessage.Parameters["id_token_hint"] = result.Properties.Dictionary[OpenIdConnectParameterNames.IdToken];
                            }
                            else if (ctx.Request.Path.Value == "/Account/Refresh")
                                ctx.ProtocolMessage.Parameters["prompt"] = "none";
                        },
                        AuthenticationFailed = async c =>
                        {
                            var state = GetPropertiesFromState(c.ProtocolMessage.State, c.Options);
                            if (state.Dictionary["prompt"] == "none")
                                c.Response.Redirect(state.RedirectUri);
                            c.HandleResponse();
                        },
                        SecurityTokenValidated = async n =>
                        {
                            var claims = n.AuthenticationTicket.Identity.Claims.ToArray();
                            foreach (var claim in claims)
                                n.AuthenticationTicket.Identity.RemoveClaim(claim);


                            n.AuthenticationTicket.Identity.AddClaim(new Claim("regionName", "Питер"));


                        }
                    },
                    TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        NameClaimType = "name",

                    },
                    // More information on why the CookieManager needs to be set can be found here: 
                    // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                    CookieManager = new RootDomainCookieManger(new SameSiteCookieManager(new ChunkingCookieManager()))
                });


                app.SetDefaultSignInAsAuthenticationType("Temporary");
            });

            
                app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                    LoginPath = new PathString("/Account/Login"),
                    CookieSameSite = SameSiteMode.Lax,
                    // More information on why the CookieManager needs to be set can be found here: 
                    // https://github.com/aspnet/AspNetKatana/wiki/System.Web-response-cookie-integration-issues
                    CookieManager = new SameSiteCookieManager(new ChunkingCookieManager()),
                    TicketDataFormat = TicketFormat,
                    Provider = new CookieAuthenticationProvider()
                    {
                        OnValidateIdentity = async ctx =>
                        {
                            ctx.Identity.AddClaim(new Claim("Virtual", "test"));

                            if (DateTime.Parse(ctx.Properties.Dictionary["expires_at"]) < DateTime.Now)
                                ctx.OwinContext.Authentication.Challenge(new AuthenticationProperties
                                {
                                    RedirectUri = "/Account/Refresh?returnUrl=" + Uri.UnescapeDataString(ctx.OwinContext.Request.Uri.ToString()),
                                }, CookieAuthenticationDefaults.AuthenticationType);
                        },
                        OnApplyRedirect = e =>
                        {
                            if (e.Request.Headers["X-Requested-With"] != "XMLHttpRequest" && e.Request.Method == "GET")
                                e.Response.Redirect(e.RedirectUri);
                        }
                    }
                });
        }


        private AuthenticationProperties GetPropertiesFromState(string state, OpenIdConnectAuthenticationOptions options)
        {
            // assume a well formed query string: <a=b&>OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey=kasjd;fljasldkjflksdj<&c=d>
            int startIndex = 0;
            if (string.IsNullOrWhiteSpace(state) || (startIndex = state.IndexOf("OpenIdConnect.AuthenticationProperties", StringComparison.Ordinal)) == -1)
            {
                return null;
            }

            int authenticationIndex = startIndex + "OpenIdConnect.AuthenticationProperties".Length;
            if (authenticationIndex == -1 || authenticationIndex == state.Length || state[authenticationIndex] != '=')
            {
                return null;
            }

            // scan rest of string looking for '&'
            authenticationIndex++;
            int endIndex = state.Substring(authenticationIndex, state.Length - authenticationIndex).IndexOf("&", StringComparison.Ordinal);

            // -1 => no other parameters are after the AuthenticationPropertiesKey
            if (endIndex == -1)
            {
                return options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex).Replace('+', ' ')));
            }
            else
            {
                return options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex, endIndex).Replace('+', ' ')));
            }
        }
    }


}
