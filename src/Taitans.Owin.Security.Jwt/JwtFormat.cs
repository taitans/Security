using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Taitans.Owin.Security.Jwt
{
    public class JwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly TokenValidationParameters _validationParameters;

        private readonly string _symmetricKeyAsBase64;

        private readonly string _audienceId;

        private readonly string _issuer;

        private JwtSecurityTokenHandler _tokenHandler;

        public JwtSecurityTokenHandler TokenHandler
        {
            get
            {
                return this._tokenHandler;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                this._tokenHandler = value;
            }
        }

        /// <summary>
        /// Indicates that the authentication session lifetime (e.g. cookies) should match that of the authentication token.
        /// If the token does not provide lifetime information then normal session lifetimes will be used.
        /// This is enabled by default.
        /// </summary>
        public bool UseTokenLifetime
        {
            get;
            set;
        }

        public string Protect(AuthenticationTicket data)
        {
            throw new NotImplementedException();
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            if (string.IsNullOrWhiteSpace(protectedText))
            {
                throw new ArgumentNullException("protectedText");
            }
            if (!(this.TokenHandler.ReadToken(protectedText) is JwtSecurityToken))
            {
                throw new ArgumentOutOfRangeException("protectedText", "Exception_InvalidJwt");
            }


            var keyByteArray = System.Text.Encoding.ASCII.GetBytes(_symmetricKeyAsBase64);
            var securityKey = new SymmetricSecurityKey(keyByteArray);

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = securityKey,
                ValidAudience = _audienceId,
                ValidIssuer = _issuer
            };


            SecurityToken securityToken;
            ClaimsPrincipal claimsPrincipal = this.TokenHandler.ValidateToken(protectedText, tokenValidationParameters, out securityToken);

            ClaimsIdentity identity = (ClaimsIdentity)claimsPrincipal.Identity;

            AuthenticationProperties authenticationProperties = new AuthenticationProperties();
            if (this.UseTokenLifetime)
            {
                DateTime validFrom = securityToken.ValidFrom;
                if (validFrom != DateTime.MinValue)
                {
                    authenticationProperties.IssuedUtc = new DateTimeOffset?(validFrom.ToUniversalTime());
                }
                DateTime validTo = securityToken.ValidTo;
                if (validTo != DateTime.MinValue)
                {
                    authenticationProperties.ExpiresUtc = new DateTimeOffset?(validTo.ToUniversalTime());
                }
                authenticationProperties.AllowRefresh = new bool?(false);
            }
            return new AuthenticationTicket(identity, authenticationProperties);
        }

        /// <summary>
        /// Creates a new JwtFormat with TokenHandler and UseTokenLifetime enabled by default.
        /// </summary>
        protected JwtFormat()
        {
            this.TokenHandler = new JwtSecurityTokenHandler();
            this.UseTokenLifetime = true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:Taitans.Owin.Security.Jwt.JwtFormat" /> class.
        /// </summary>
        /// <param name="validationParameters"> <see cref="T:System.IdentityModel.Tokens.TokenValidationParameters" /> used to determine if a token is valid.</param>
        /// <exception cref="T:System.ArgumentNullException">Thrown if the <paramref name="validationParameters" /> is null.</exception>
        public JwtFormat(TokenValidationParameters validationParameters) : this()
        {
            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }
            this._validationParameters = validationParameters;
            if (string.IsNullOrWhiteSpace(this._validationParameters.AuthenticationType))
            {
                this._validationParameters.AuthenticationType = "JWT";
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:Taitans.Owin.Security.Jwt.JwtFormat" /> class.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="audienceId"></param>
        /// <param name="symmetricKeyAsBase64"></param>
        /// <param name="validationParameters"></param>
        public JwtFormat(string issuer, string audienceId, string symmetricKeyAsBase64, TokenValidationParameters validationParameters) : this(validationParameters)
        {
            _audienceId = audienceId;

            _symmetricKeyAsBase64 = symmetricKeyAsBase64;

            _issuer = issuer;

        }
    }
}
