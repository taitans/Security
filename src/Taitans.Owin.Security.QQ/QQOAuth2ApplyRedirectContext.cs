using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Taitans.Owin.Security.QQ
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the QQ OAuth 2.0 middleware
    /// </summary>
    public class QQOAuth2ApplyRedirectContext : BaseContext<QQOAuth2AuthenticationOptions>
    {
        /// <summary>
		/// Gets the URI used for the redirect operation.
		/// </summary>
		public string RedirectUri
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the authenticaiton properties of the challenge
        /// </summary>
        public AuthenticationProperties Properties
        {
            get;
            private set;
        }

        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The OWIN request context</param>
        /// <param name="options">The QQ OAuth 2.0 middleware options</param>
        /// <param name="properties">The authenticaiton properties of the challenge</param>
        /// <param name="redirectUri">The initial redirect URI</param>
        public QQOAuth2ApplyRedirectContext(IOwinContext context, QQOAuth2AuthenticationOptions options, AuthenticationProperties properties, string redirectUri) : base(context, options)
		{
            this.RedirectUri = redirectUri;
            this.Properties = properties;
        }
    }
}
