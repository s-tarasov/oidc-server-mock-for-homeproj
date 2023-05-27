using System.Reflection;
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

    public class CustomOpenIdConnectAuthenticationHandler : OpenIdConnectAuthenticationHandler, IRefreshTokenInvoker
    {
        public CustomOpenIdConnectAuthenticationHandler(ILogger logger) : base(logger)
        {
        }

        private static readonly FieldInfo _configurationField = typeof(OpenIdConnectAuthenticationHandler).GetField("_configuration", BindingFlags.NonPublic | BindingFlags.Instance);

        private OpenIdConnectConfiguration Configuration
        {
            get => (OpenIdConnectConfiguration)_configurationField.GetValue(this);
            set => _configurationField.SetValue(this, value);
        }

        public async Task<OpenIdConnectMessage> GetTokensAsync(string refreshToken)
        {
            if (Configuration == null)
                Configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
            

            var tokenEndpointRequest = new OpenIdConnectMessage
            {
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                RefreshToken = refreshToken,
                GrantType = OpenIdConnectGrantTypes.RefreshToken
            };

            return await RedeemAuthorizationCodeAsync(tokenEndpointRequest);
            
        }

        protected override Task InitializeCoreAsync()
        {
            Context.Set<IRefreshTokenInvoker>(nameof(IRefreshTokenInvoker), this);
            return base.InitializeCoreAsync();
        }
    }

    public interface IRefreshTokenInvoker
    {
        Task<OpenIdConnectMessage> GetTokensAsync(string refreshToken);
    }
}
