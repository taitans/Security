using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Taitans.Owin.Security.QQ
{
    internal class QQOAuth2AuthenticationHandler : AuthenticationHandler<QQOAuth2AuthenticationOptions>
    {
        //private const string TokenEndpoint = "https://accounts.qq.com/o/oauth2/token";
        private const string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";

        //private const string UserInfoEndpoint = "https://www.qqapis.com/plus/v1/people/me";
        private const string OpenIdEndpoint = "https://graph.qq.com/oauth2.0/me";

        private const string UserInfoEndpoint = "https://graph.qq.com/user/get_user_info";

        //private const string AuthorizeEndpoint = "https://accounts.qq.com/o/oauth2/auth";
        private const string AuthorizeEndpoint = "https://graph.qq.com/oauth2.0/authorize";

        private readonly ILogger _logger;

        private readonly HttpClient _httpClient;

        public QQOAuth2AuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties authenticationProperties = null;
            AuthenticationTicket result;
            try
            {
                string value = null;
                string protectedText = null;
                IReadableStringCollection query = base.Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    value = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    protectedText = values[0];
                }
                authenticationProperties = base.Options.StateDataFormat.Unprotect(protectedText);
                if (authenticationProperties == null)
                {
                    result = null;
                }
                else if (!base.ValidateCorrelationId(authenticationProperties, this._logger))
                {
                    result = new AuthenticationTicket(null, authenticationProperties);
                }
                else
                {
                    string arg = base.Request.Scheme + "://" + base.Request.Host;
                    string value2 = arg + base.RequestPathBase + base.Options.CallbackPath;
                    List<KeyValuePair<string, string>> list = new List<KeyValuePair<string, string>>();
                    list.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                    list.Add(new KeyValuePair<string, string>("code", value));
                    list.Add(new KeyValuePair<string, string>("redirect_uri", value2));
                    list.Add(new KeyValuePair<string, string>("client_id", base.Options.ClientId));
                    list.Add(new KeyValuePair<string, string>("client_secret", base.Options.ClientSecret));
                    HttpResponseMessage httpResponseMessage = await this._httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(list));
                    httpResponseMessage.EnsureSuccessStatusCode();
                    string text = await TokenToJsonText(await httpResponseMessage.Content.ReadAsStringAsync());
                    JObject jObject = JObject.Parse(text);
                    string text2 = jObject.Value<string>("access_token");
                    if (string.IsNullOrWhiteSpace(text2))
                    {
                        LoggerExtensions.WriteWarning(this._logger, "Access token was not found", new string[0]);
                        result = new AuthenticationTicket(null, authenticationProperties);
                    }
                    else
                    {
                        HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, $"{OpenIdEndpoint}?access_token={text2}");
                        //httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", text2);
                        HttpResponseMessage httpResponseMessage2 = await this._httpClient.SendAsync(httpRequestMessage, base.Request.CallCancelled);
                        httpResponseMessage2.EnsureSuccessStatusCode();
                        text = await OpenIdToJsonText(await httpResponseMessage2.Content.ReadAsStringAsync());
                        jObject = JObject.Parse(text);
                        string openid = jObject.Value<string>("openid");
                        if (string.IsNullOrWhiteSpace(openid))
                        {
                            LoggerExtensions.WriteWarning(this._logger, "Access token was not found", new string[0]);
                            result = new AuthenticationTicket(null, authenticationProperties);
                        }
                        else
                        {
                            httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, $"{UserInfoEndpoint}?access_token={text2}&oauth_consumer_key={base.Options.ClientId}&openid={openid}");
                            httpResponseMessage2 = await this._httpClient.SendAsync(httpRequestMessage, base.Request.CallCancelled);

                            text = await httpResponseMessage2.Content.ReadAsStringAsync();
                            JObject user = JObject.Parse(text);
                            QQOAuth2AuthenticatedContext qqOAuth2AuthenticatedContext = new QQOAuth2AuthenticatedContext(base.Context, openid, user, jObject);
                            qqOAuth2AuthenticatedContext.Identity = new ClaimsIdentity(base.Options.AuthenticationType, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Id))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", qqOAuth2AuthenticatedContext.Id, "http://www.w3.org/2001/XMLSchema#string", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Name))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", qqOAuth2AuthenticatedContext.Name, "http://www.w3.org/2001/XMLSchema#string", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Email))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", qqOAuth2AuthenticatedContext.Email, "http://www.w3.org/2001/XMLSchema#string", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Gender))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:gender", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#gender", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Province))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:province", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#province", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.City))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:city", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#city", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Year))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:year", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#year", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Figureurl))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:figureurl", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#figureurl", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Figureurl_1))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:figureurl_1", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#figureurl_1", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Figureurl_2))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:figureurl_2", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#figureurl_2", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Figureurl_QQ_1))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:figureurl_qq_1", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#figureurl_qq_1", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Figureurl_QQ_2))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:figureurl_qq_2", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#figureurl_qq_2", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.IsYellowVip))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:is_yellow_vip", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#is_yellow_vip", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Vip))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:vip", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#vip", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.YellowVipLevel))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:yellow_vip_level", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#yellow_vip_level", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.Level))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:level", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#level", base.Options.AuthenticationType));
                            }
                            if (!string.IsNullOrEmpty(qqOAuth2AuthenticatedContext.IsYellowYearVip))
                            {
                                qqOAuth2AuthenticatedContext.Identity.AddClaim(new Claim("urn:qq:is_yellow_year_vip", qqOAuth2AuthenticatedContext.City, "http://www.w3.org/2001/XMLSchema#is_yellow_year_vip", base.Options.AuthenticationType));
                            }
                            qqOAuth2AuthenticatedContext.Properties = authenticationProperties;
                            await base.Options.Provider.Authenticated(qqOAuth2AuthenticatedContext);
                            result = new AuthenticationTicket(qqOAuth2AuthenticatedContext.Identity, qqOAuth2AuthenticatedContext.Properties);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LoggerExtensions.WriteError(this._logger, "Authentication failed", ex);
                result = new AuthenticationTicket(null, authenticationProperties);
            }
            return result;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (base.Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }
            AuthenticationResponseChallenge authenticationResponseChallenge = base.Helper.LookupChallenge(base.Options.AuthenticationType, base.Options.AuthenticationMode);
            if (authenticationResponseChallenge != null)
            {
                string arg = string.Concat(new object[]
                {
                    base.Request.Scheme,
                    Uri.SchemeDelimiter,
                    base.Request.Host,
                    base.Request.PathBase
                });
                string redirectUri = arg + base.Request.Path + base.Request.QueryString;
                string value = arg + base.Options.CallbackPath;
                AuthenticationProperties properties = authenticationResponseChallenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = redirectUri;
                }
                base.GenerateCorrelationId(properties);
                Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                dictionary.Add("response_type", "code");
                dictionary.Add("client_id", base.Options.ClientId);
                dictionary.Add("redirect_uri", value);
                string text = string.Join(" ", base.Options.Scope);
                if (string.IsNullOrEmpty(text))
                {
                    text = "get_user_info,get_info,add_t,del_t,add_pic_t,get_repost_list";
                }
                QQOAuth2AuthenticationHandler.AddQueryString(dictionary, properties, "scope", text);
                string value2 = base.Options.StateDataFormat.Protect(properties);
                dictionary.Add("state", value2);
                string redirectUri2 = AddQueryString(AuthorizeEndpoint, dictionary);
                QQOAuth2ApplyRedirectContext context = new QQOAuth2ApplyRedirectContext(base.Context, base.Options, properties, redirectUri2);
                base.Options.Provider.ApplyRedirect(context);
            }
            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await this.InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            bool result;
            if (base.Options.CallbackPath.HasValue && base.Options.CallbackPath == base.Request.Path)
            {
                AuthenticationTicket authenticationTicket = await base.AuthenticateAsync();
                if (authenticationTicket == null)
                {
                    LoggerExtensions.WriteWarning(this._logger, "Invalid return state, unable to redirect.", new string[0]);
                    base.Response.StatusCode = 500;
                    result = true;
                }
                else
                {
                    QQOAuth2ReturnEndpointContext qqOAuth2ReturnEndpointContext = new QQOAuth2ReturnEndpointContext(base.Context, authenticationTicket);
                    qqOAuth2ReturnEndpointContext.SignInAsAuthenticationType = base.Options.SignInAsAuthenticationType;
                    qqOAuth2ReturnEndpointContext.RedirectUri = authenticationTicket.Properties.RedirectUri;
                    await base.Options.Provider.ReturnEndpoint(qqOAuth2ReturnEndpointContext);
                    if (qqOAuth2ReturnEndpointContext.SignInAsAuthenticationType != null && qqOAuth2ReturnEndpointContext.Identity != null)
                    {
                        ClaimsIdentity claimsIdentity = qqOAuth2ReturnEndpointContext.Identity;
                        if (!string.Equals(claimsIdentity.AuthenticationType, qqOAuth2ReturnEndpointContext.SignInAsAuthenticationType, StringComparison.Ordinal))
                        {
                            claimsIdentity = new ClaimsIdentity(claimsIdentity.Claims, qqOAuth2ReturnEndpointContext.SignInAsAuthenticationType, claimsIdentity.NameClaimType, claimsIdentity.RoleClaimType);
                        }
                        base.Context.Authentication.SignIn(qqOAuth2ReturnEndpointContext.Properties, new ClaimsIdentity[]
                        {
                            claimsIdentity
                        });
                    }
                    if (!qqOAuth2ReturnEndpointContext.IsRequestCompleted && qqOAuth2ReturnEndpointContext.RedirectUri != null)
                    {
                        string text = qqOAuth2ReturnEndpointContext.RedirectUri;
                        if (qqOAuth2ReturnEndpointContext.Identity == null)
                        {
                            text = AddQueryString(text, "error", "access_denied");
                        }
                        base.Response.Redirect(text);
                        qqOAuth2ReturnEndpointContext.RequestCompleted();
                    }
                    result = qqOAuth2ReturnEndpointContext.IsRequestCompleted;
                }
            }
            else
            {
                result = false;
            }
            return result;
        }

        private async Task<string> TokenToJsonText(string text)
        {
            string[] textSplit = text.Split('&');
            Dictionary<string, string> textdir = new Dictionary<string, string>();
            foreach (var item in textSplit)
            {
                string[] split = item.Split('=');
                textdir.Add(split[0], split[1]);
            }
            return await Task.Factory.StartNew(() => JsonConvert.SerializeObject(textdir));
        }

        private async Task<string> OpenIdToJsonText(string text)
        {
            return await Task.Factory.StartNew(() =>
            {
                text = text.Replace("callback(", "");
                text = text.Replace(");", "");
                return text;
            });
        }

        private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties, string name, string defaultValue = null)
        {
            string text;
            if (!properties.Dictionary.TryGetValue(name, out text))
            {
                text = defaultValue;
            }
            else
            {
                properties.Dictionary.Remove(name);
            }
            if (text == null)
            {
                return;
            }
            queryStrings[name] = text;
        }

        #region Tencet Method
        private string AddQueryString(string uri, IDictionary<string, string> queryString)
        {
            if (uri == null)
            {
                throw new ArgumentNullException("uri");
            }
            if (queryString == null)
            {
                throw new ArgumentNullException("queryString");
            }
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append(uri);
            bool flag = uri.IndexOf('?') != -1;
            foreach (KeyValuePair<string, string> current in queryString)
            {
                stringBuilder.Append(flag ? '&' : '?');
                stringBuilder.Append(current.Key);
                stringBuilder.Append('=');
                stringBuilder.Append(current.Value);
                flag = true;
            }
            return stringBuilder.ToString();
        }
        public static string AddQueryString(string uri, string name, string value)
        {
            if (uri == null)
            {
                throw new ArgumentNullException("uri");
            }
            if (name == null)
            {
                throw new ArgumentNullException("name");
            }
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            bool flag = uri.IndexOf('?') != -1;
            return string.Concat(new string[]
            {
                uri,
                flag ? "&" : "?",
                Uri.EscapeDataString(name),
                "=",
                Uri.EscapeDataString(value)
            });
        }
        #endregion
    }
}
