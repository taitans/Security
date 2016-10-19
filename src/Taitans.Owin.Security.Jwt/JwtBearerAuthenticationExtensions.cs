using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;

namespace Taitans.Owin.Security.Jwt
{
    public static class JwtBearerAuthenticationExtensions
    {
        /// <summary>
        ///  Adds JWT bearer token middleware to your web application pipeline.
        /// </summary>
        /// <param name="app"></param>
        /// <param name="issuer"></param>
        /// <param name="audienceId"></param>
        /// <param name="symmetricKeyAsBase64"></param>
        /// <param name="validationParameters"></param>
        /// <returns></returns>
        public static IAppBuilder UseJwtBearerAuthentication(this IAppBuilder app, string issuer, string audienceId, string symmetricKeyAsBase64, TokenValidationParameters validationParameters)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            JwtFormat jwtFormat = new JwtFormat(issuer, audienceId, symmetricKeyAsBase64, validationParameters);
            
            OAuthBearerAuthenticationOptions options2 = new OAuthBearerAuthenticationOptions()
            {
                AccessTokenFormat = jwtFormat
            };
            app.UseOAuthBearerAuthentication(options2);

            return app;
        }
    }
}
