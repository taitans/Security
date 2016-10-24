using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Taitans.Owin.Security.QQ
{
    /// <summary>
	/// Configuration options for <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticationMiddleware" />
	/// </summary>
    public class QQOAuth2AuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
		/// Gets or sets the QQ-assigned client id
		/// </summary>
		public string ClientId
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the QQ-assigned client secret
        /// </summary>
        public string ClientSecret
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to QQ.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with QQ.
        /// </summary>
        /// <value>
        /// The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout
        {
            get;
            set;
        }

        /// <summary>
        /// The HttpMessageHandler used to communicate with QQ.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler
        {
            get;
            set;
        }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get
            {
                return base.Description.Caption;
            }
            set
            {
                base.Description.Caption = value;
            }
        }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-QQ".
        /// </summary>
        public PathString CallbackPath
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="T:System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="T:Taitans.Owin.Security.QQ.IQQOAuth2AuthenticationProvider" /> used to handle authentication events.
        /// </summary>
        public IQQOAuth2AuthenticationProvider Provider
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat
        {
            get;
            set;
        }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope
        {
            get;
            private set;
        }

        /// <summary>
        /// access_type. Set to 'offline' to request a refresh token.
        /// </summary>
        public string AccessType
        {
            get;
            set;
        }

        /// <summary>
        /// Initializes a new <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticationOptions" />
        /// </summary>
        public QQOAuth2AuthenticationOptions() : base("QQ")
        {
            this.Caption = "QQ";
            this.CallbackPath = new PathString("/signinQQ");
            base.AuthenticationMode = AuthenticationMode.Passive;
            this.Scope = new List<string>();
            this.BackchannelTimeout = TimeSpan.FromSeconds(60.0);
        }
    }
}
