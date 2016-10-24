using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Taitans.Owin.Security.QQ;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="T:Taitans.Owin.Security.QQ.QQAuthenticationMiddleware" />
    /// </summary>
    public static class QQAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using QQ OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="T:Owin.IAppBuilder" /> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="T:Owin.IAppBuilder" /></returns>
        public static IAppBuilder UseQQAuthentication(this IAppBuilder app, QQOAuth2AuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            app.Use(typeof(QQOAuth2AuthenticationMiddleware), new object[]
            {
                app,
                options
            });
            return app;
        }

        /// <summary>
		/// Authenticate users using QQ OAuth 2.0
		/// </summary>
		/// <param name="app">The <see cref="T:Owin.IAppBuilder" /> passed to the configuration method</param>
		/// <param name="appId">The QQ assigned appId</param>
		/// <param name="appKey">The QQ assigned appKey</param>
		/// <returns>The updated <see cref="T:Owin.IAppBuilder" /></returns>
		public static IAppBuilder UseQQAuthentication(this IAppBuilder app, string appId, string appKey)
        {
            return app.UseQQAuthentication(new QQOAuth2AuthenticationOptions
            {
                ClientId = appId,
                ClientSecret = appKey
            });
        }
    }
}
