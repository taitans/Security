Taitans Security
================

Build:[![Build status](https://ci.appveyor.com/api/projects/status/m46qdo22qbu62hbu/branch/master?svg=true)](https://ci.appveyor.com/project/xielongjiang/security/branch/master)

## Change Logs  

### 2018-04-08 

* Update Taitans.Owin.Security.Aes project depend on the package for reference. 
* Update Taitans.Owin.Security.Jwt project depend on the package for reference. 
* Update Taitans.Owin.Security.QQ project depend on the package for reference. 

### 2016-10-24 

* Add the `Taitans.Owin.Security.QQ` project 

## Instructions 

When you use OWIN middleware using Json Web Token deployment in Mono environment, it will be a serious mistake  `Could not load type "Microsoft.Owin.Security.DataProtection.DpapiDataProtector"`

If you use a System.IdentityModel.Tokens.Jwt >=5.0 version, then you will result in a Cannt find the assembly error.

Don't ask me why, please see the official to [answer](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/512#issuecomment-252789324)

The project to solve when you are in the use of `UseJwtBearerAuthentication` will not happen error

When you need to deploy in Mono environment, will have a more serious error

## Part of the code

### Security

```net
//This allows you to program deployed in mono
app.UseAesDataProtectionProvider("your name"); 



var issuer = "http://localhost:8888";

string audienceId = ConfigurationManager.AppSettings["as:AudienceId"];

string symmetricKeyAsBase64 = ConfigurationManager.AppSettings["as:AudienceSecret"];

byte[] audienceSecret = System.Text.Encoding.ASCII.GetBytes(symmetricKeyAsBase64);

var securityKey = new SymmetricSecurityKey(audienceSecret);

TokenValidationParameters validationParameters = new TokenValidationParameters
{
   IssuerSigningKey = securityKey,
   ValidAudience = audienceId,
   ValidIssuer = issuer
};
app.UseJwtBearerAuthentication(issuer, audienceId, symmetricKeyAsBase64, validationParameters);
```

### QQ Connect

```net
 app.UseQQAuthentication(new QQOAuth2AuthenticationOptions
 {
   ClientId = "your appId",
   ClientSecret = "your appKey"
 });
```
