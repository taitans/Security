using System;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using System.IdentityModel.Tokens.Jwt;

namespace Taitans.Owin.Security.Jwt.Tests
{

    public class UseJwtBearerAuthenticationTest
    {
        [Fact]
        public void SB()
        {
            var keyByteArray = System.Text.Encoding.ASCII.GetBytes("qMCdFDQuF23RV1Y-1Gq9L3cF3VmuFwVbam4fMTdAfcc");

            var audienceid = "414e1927a3884f68abc79f7283837fd2";

            var issuer = "http://www.abc.com";

            var securityKey = new SymmetricSecurityKey(keyByteArray);

            var sigigCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            JwtSecurityToken token = handler.CreateJwtSecurityToken(issuer, audienceid, null, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1), DateTime.UtcNow + TimeSpan.FromHours(1), sigigCredentials);

            string jwt = handler.WriteToken(token);


            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = securityKey,
                ValidAudience = audienceid,
                ValidIssuer = issuer
            };

            SecurityToken securityToken = null;
            handler.ValidateToken(jwt, tokenValidationParameters, out securityToken);

            bool istrue = securityToken.Issuer == issuer ? true : false;
            Assert.True(istrue);



        }
    }
}
