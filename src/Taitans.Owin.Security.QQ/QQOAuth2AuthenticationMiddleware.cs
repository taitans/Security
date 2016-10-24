using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Globalization;
using System.Net.Http;
using System.Net.Security;

namespace Taitans.Owin.Security.QQ
{
    /// <summary>
    ///  OWIN middleware for authenticating users using QQ OAuth 2.0
    /// </summary>
    public class QQOAuth2AuthenticationMiddleware : AuthenticationMiddleware<QQOAuth2AuthenticationOptions>
    {
        private readonly ILogger _logger;

        private readonly HttpClient _httpClient;

        /// <summary>
        /// Initializes a <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticationMiddleware" />
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public QQOAuth2AuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, QQOAuth2AuthenticationOptions options) : base(next, options)
		{
            if (string.IsNullOrWhiteSpace(base.Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", new object[]
                {
                    "ClientId"
                }));
            }
            if (string.IsNullOrWhiteSpace(base.Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", new object[]
                {
                    "ClientSecret"
                }));
            }
            this._logger = AppBuilderLoggerExtensions.CreateLogger<QQOAuth2AuthenticationMiddleware>(app);
            if (base.Options.Provider == null)
            {
                base.Options.Provider = new QQOAuth2AuthenticationProvider();
            }
            if (base.Options.StateDataFormat == null)
            {
                IDataProtector protector = app.CreateDataProtector(new string[]
                {
                    typeof(QQOAuth2AuthenticationMiddleware).FullName,
                    base.Options.AuthenticationType,
                    "v1"
                });
                base.Options.StateDataFormat = new PropertiesDataFormat(protector);
            }
            if (string.IsNullOrEmpty(base.Options.SignInAsAuthenticationType))
            {
                base.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
            this._httpClient = new HttpClient(QQOAuth2AuthenticationMiddleware.ResolveHttpMessageHandler(base.Options));
            this._httpClient.Timeout = base.Options.BackchannelTimeout;
            this._httpClient.MaxResponseContentBufferSize = 10485760L;
        }

        /// <summary>
        /// Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the <see cref="T:Microsoft.Owin.Security.QQ.QQOAuth2AuthenticationOptions" /> supplied to the constructor.</returns>
        protected override AuthenticationHandler<QQOAuth2AuthenticationOptions> CreateHandler()
        {
            return new QQOAuth2AuthenticationHandler(this._httpClient, this._logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(QQOAuth2AuthenticationOptions options)
        {
            HttpMessageHandler httpMessageHandler = options.BackchannelHttpHandler ?? new WebRequestHandler();
            if (options.BackchannelCertificateValidator != null)
            {
                WebRequestHandler webRequestHandler = httpMessageHandler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebReuestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(options.BackchannelCertificateValidator.Validate);
            }
            return httpMessageHandler;
        }
    }
}
