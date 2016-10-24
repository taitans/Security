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
    ///  Provides context information to middleware providers.
    /// </summary>
    public class QQOAuth2ReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
		/// Initialize a <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2ReturnEndpointContext" />
		/// </summary>
		/// <param name="context">OWIN environment</param>
		/// <param name="ticket">The authentication ticket</param>
		public QQOAuth2ReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
		{
        }
    }
}
