using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Privacy");
});

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"c:\Temp\Rings"))
    .SetApplicationName("SharedCookieApp");

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.Name = ".AspNet.Cookies";
        options.Events.OnRedirectToLogin = async ctx =>
        {
            if (ctx.Request.Headers["X-Requested-With"] != "XMLHttpRequest" && ctx.Request.Method == "GET")
            {
                if (ctx.Properties.RedirectUri is not null)
                    ctx.Response.Redirect(ctx.Properties.RedirectUri);
                else
                {
                    var relativeRedirectUri = new Uri(ctx.RedirectUri, UriKind.RelativeOrAbsolute).IsAbsoluteUri
                        ? new Uri(ctx.RedirectUri).PathAndQuery
                        : ctx.RedirectUri;

                    if (relativeRedirectUri.StartsWith("/passive6/", StringComparison.InvariantCultureIgnoreCase))
                        relativeRedirectUri = relativeRedirectUri.Substring("/passive6".Length);

                    ctx.Response.Redirect(relativeRedirectUri);
                }
            }
        };
        options.Events.OnValidatePrincipal = async ctx =>
        {
            var exp = DateTime.Parse(ctx.Properties.Items["expires_at"]);
            if (exp < DateTime.Now)
                await ctx.HttpContext.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties
                {
                    RedirectUri = "/Account/Refresh?returnUrl=" + Uri.EscapeDataString(ctx.Request.GetEncodedUrl()),
                });

        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
