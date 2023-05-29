using System;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;

namespace MVC5Client.Misc
{
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

        protected async override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var ticket = await base.AuthenticateCoreAsync();
            if (ticket == null)
                return null;

            ticket.Properties.Dictionary["region"] = "spb2";

            var redirectUri = new Uri(ticket.Properties.RedirectUri, UriKind.RelativeOrAbsolute);

            var relativeRedirectUri = redirectUri.IsAbsoluteUri ? redirectUri.PathAndQuery : redirectUri.ToString();
            var baseUri = new Uri("http://spb.multidomainapp.local:3000/");
            var relativeSubdomainCallbackUri = "/Account/SubdomainCallback?redirectUri="
                + Uri.EscapeDataString(relativeRedirectUri);
            ticket.Properties.RedirectUri = new Uri(baseUri, relativeSubdomainCallbackUri).ToString();
            return ticket;
        }
    }
}
