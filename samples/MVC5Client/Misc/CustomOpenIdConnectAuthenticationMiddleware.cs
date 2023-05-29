using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace MVC5Client.Misc
{
    public class CustomOpenIdConnectAuthenticationMiddleware : OpenIdConnectAuthenticationMiddleware
    {
        private readonly ILogger _logger;

        public CustomOpenIdConnectAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, OpenIdConnectAuthenticationOptions options)
            : base(next, app, options)
        {
            _logger = app.CreateLogger<OpenIdConnectAuthenticationMiddleware>();
        }

        public override Task Invoke(IOwinContext context)
        {
            return base.Invoke(context);
        }

        protected override AuthenticationHandler<OpenIdConnectAuthenticationOptions> CreateHandler()
        {
             return new CustomOpenIdConnectAuthenticationHandler(_logger);
        }
    }

    public interface IRefreshTokenInvoker
    {
        Task<OpenIdConnectMessage> GetTokensAsync(string refreshToken);
    }
}
