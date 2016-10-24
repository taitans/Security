using System.Threading.Tasks;

namespace Taitans.Owin.Security.QQ
{
    /// <summary>
	/// Specifies callback methods which the <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. /&gt;
	/// </summary>
    public interface IQQOAuth2AuthenticationProvider
    {
        /// <summary>
		/// Invoked whenever QQ succesfully authenticates a user
		/// </summary>
		/// <param name="context">Contains information about the login session as well as the user <see cref="T:System.Security.Claims.ClaimsIdentity" />.</param>
		/// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.</returns>
		Task Authenticated(QQOAuth2AuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="T:System.Security.Claims.ClaimsIdentity" /> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Contains context information and authentication ticket of the return endpoint.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.</returns>
        Task ReturnEndpoint(QQOAuth2ReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the QQ OAuth 2.0 middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="T:Microsoft.Owin.Security.AuthenticationProperties" /> of the challenge </param>
        void ApplyRedirect(QQOAuth2ApplyRedirectContext context);
    }
}
