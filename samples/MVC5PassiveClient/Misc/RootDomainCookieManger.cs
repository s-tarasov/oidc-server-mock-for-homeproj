
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin;

namespace MVC5Client.Misc
{
    public class RootDomainCookieManger : ICookieManager
    {
        private readonly ICookieManager _innerManager;

        public RootDomainCookieManger() : this(new CookieManager())
        {
        }

        public RootDomainCookieManger(ICookieManager innerManager)
        {
            _innerManager = innerManager;
        }

        public void AppendResponseCookie(IOwinContext context, string key, string value,
                                         CookieOptions options)
        {
            SubdomainSupport(context, options);
            _innerManager.AppendResponseCookie(context, key, value, options);
        }

        public void DeleteCookie(IOwinContext context, string key, CookieOptions options)
        {
            SubdomainSupport(context, options);
            _innerManager.DeleteCookie(context, key, options);
        }

        public string GetRequestCookie(IOwinContext context, string key)
        {
            return _innerManager.GetRequestCookie(context, key);
        }

        // for subdomain support
        private void SubdomainSupport(IOwinContext context, CookieOptions options)
        {
            options.Domain = ".multidomainapp.local";
        }
    }
}
