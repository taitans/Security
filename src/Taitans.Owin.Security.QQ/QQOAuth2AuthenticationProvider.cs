using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Taitans.Owin.Security.QQ
{
    /// <summary>
    /// Default <see cref="T:Taitans.Owin.Security.QQ.IQQOAuth2AuthenticationProvider" /> implementation.
    /// </summary>
    public class QQOAuth2AuthenticationProvider : IQQOAuth2AuthenticationProvider
    {
        /// <summary>
		/// Gets or sets the function that is invoked when the Authenticated method is invoked.
		/// </summary>
		public Func<QQOAuth2AuthenticatedContext, Task> OnAuthenticated
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<QQOAuth2ReturnEndpointContext, Task> OnReturnEndpoint
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<QQOAuth2ApplyRedirectContext> OnApplyRedirect
        {
            get;
            set;
        }

        /// <summary>
        /// Initializes a <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticationProvider" />
        /// </summary>
        public QQOAuth2AuthenticationProvider()
        {
            this.OnAuthenticated = ((QQOAuth2AuthenticatedContext context) => Task.FromResult<object>(null));
            this.OnReturnEndpoint = ((QQOAuth2ReturnEndpointContext context) => Task.FromResult<object>(null));
            this.OnApplyRedirect = delegate (QQOAuth2ApplyRedirectContext context)
            {
                context.Response.Redirect(context.RedirectUri);
            };
        }

        /// <summary>
        /// Invoked whenever QQ succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="T:System.Security.Claims.ClaimsIdentity" />.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.</returns>
        public virtual Task Authenticated(QQOAuth2AuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="T:System.Security.Claims.ClaimsIdentity" /> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Contains context information and authentication ticket of the return endpoint.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(QQOAuth2ReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the QQ OAuth 2.0 middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="T:Microsoft.Owin.Security.AuthenticationProperties" /> of the challenge </param>
        public virtual void ApplyRedirect(QQOAuth2ApplyRedirectContext context)
        {
            this.OnApplyRedirect(context);
        }
    }
}
