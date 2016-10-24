using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;

namespace Taitans.Owin.Security.QQ
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="T:System.Security.Claims.ClaimsIdentity" />.
    /// </summary>
    public class QQOAuth2AuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the QQ user obtained from the endpoint https://www.googleapis.com/oauth2/v3/userinfo
        /// </remarks>
        public JObject User
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the QQ access token
        /// </summary>
        public string AccessToken
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the QQ refresh token
        /// </summary>
        /// <remarks>
        /// This value is not null only when access_type authorize parameter is offline.
        /// </remarks>
        public string RefreshToken
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the QQ access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the QQ user ID
        /// </summary>
        public string Id
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's city
        /// </summary>
        public string City
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the user's province
        /// </summary>
        public string Province
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the user's year
        /// </summary>
        public string Year
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the user's figure url
        /// </summary>
        public string Figureurl
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's figure url 1
        /// </summary>
        public string Figureurl_1
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's figure url 2
        /// </summary>
        public string Figureurl_2
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's figure url qq 1 
        /// </summary>
        public string Figureurl_QQ_1
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's figure url qq 2
        /// </summary>
        public string Figureurl_QQ_2
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's gender 
        /// If get gender is null,then return 男
        /// </summary>
        public string Gender
        {
            get;
            private set;
        }


        /// <summary>
        /// Gets the user's is yellow vip
        /// Identifies whether a user is canary users (0: no; 1: yes).
        /// </summary>
        public string IsYellowVip
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's vip
        /// Identifies whether a user is canary users (0: no; 1: yes).
        /// </summary>
        public string Vip
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's yellow vip level
        /// Canary level
        /// </summary>
        public string YellowVipLevel
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's level
        /// Canary level
        /// </summary>
        public string Level
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user's is yellow year vip
        /// Identify whether for annual fee canary users (0: no; 1: yes)
        /// </summary>
        public string IsYellowYearVip
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the <see cref="T:System.Security.Claims.ClaimsIdentity" /> representing the user
        /// </summary>
        public ClaimsIdentity Identity
        {
            get;
            set;
        }

        /// <summary>
        /// Token response from QQ
        /// </summary>
        public JObject TokenResponse
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public Microsoft.Owin.Security.AuthenticationProperties Properties
        {
            get;
            set;
        }

        /// <summary>
        /// Initializes a <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticatedContext" />
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="openId">QQ openid</param>
        /// <param name="user">The JSON-serialized QQ user info</param>
        /// <param name="accessToken">QQ OAuth 2.0 access token</param>
        /// <param name="refreshToken">Goolge OAuth 2.0 refresh token</param>
        /// <param name="expires">Seconds until expiration</param>
        public QQOAuth2AuthenticatedContext(IOwinContext context, string openId, JObject user, string accessToken, string refreshToken, string expires) : base(context)
        {
            this.User = user;
            this.AccessToken = accessToken;
            this.RefreshToken = refreshToken;
            int num;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out num))
            {
                this.ExpiresIn = new TimeSpan?(TimeSpan.FromSeconds((double)num));
            }
            this.Id = openId;
            this.Name = QQOAuth2AuthenticatedContext.TryGetValue(user, "nickname");
            this.Province = QQOAuth2AuthenticatedContext.TryGetValue(user, "province");
            this.City = QQOAuth2AuthenticatedContext.TryGetValue(user, "city");
            this.Gender = QQOAuth2AuthenticatedContext.TryGetValue(user, "gender");
            this.Year = QQOAuth2AuthenticatedContext.TryGetValue(user, "year");
            this.Figureurl = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl");
            this.Figureurl_1 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_1");
            this.Figureurl_2 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_2");
            this.Figureurl_QQ_1 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_qq_1");
            this.Figureurl_QQ_2 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_qq_2");
            this.IsYellowVip = QQOAuth2AuthenticatedContext.TryGetValue(user, "is_yellow_vip");
            this.Vip = QQOAuth2AuthenticatedContext.TryGetValue(user, "vip");
            this.YellowVipLevel = QQOAuth2AuthenticatedContext.TryGetValue(user, "yellow_vip_level");
            this.Level = QQOAuth2AuthenticatedContext.TryGetValue(user, "level");
            this.IsYellowYearVip = QQOAuth2AuthenticatedContext.TryGetValue(user, "is_yellow_year_vip");
            this.Email = Name;
        }

        /// <summary>
        /// Initializes a <see cref="T:Taitans.Owin.Security.QQ.QQOAuth2AuthenticatedContext" />
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="openId">QQ openid</param>
        /// <param name="user">The JSON-serialized QQ user info</param>
        /// <param name="tokenResponse">The JSON-serialized token response QQ</param>
        public QQOAuth2AuthenticatedContext(IOwinContext context, string openId, JObject user, JObject tokenResponse) : base(context)
        {
            this.User = user;
            this.TokenResponse = tokenResponse;
            if (tokenResponse != null)
            {
                this.AccessToken = tokenResponse.Value<string>("access_token");
                this.RefreshToken = tokenResponse.Value<string>("refresh_token");
                int num;
                if (int.TryParse(tokenResponse.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out num))
                {
                    this.ExpiresIn = new TimeSpan?(TimeSpan.FromSeconds((double)num));
                }
            }
            this.Id = openId;
            this.Name = QQOAuth2AuthenticatedContext.TryGetValue(user, "nickname");
            this.Province = QQOAuth2AuthenticatedContext.TryGetValue(user, "province");
            this.City = QQOAuth2AuthenticatedContext.TryGetValue(user, "city");
            this.Gender = QQOAuth2AuthenticatedContext.TryGetValue(user, "gender");
            this.Year = QQOAuth2AuthenticatedContext.TryGetValue(user, "year");
            this.Figureurl = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl");
            this.Figureurl_1 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_1");
            this.Figureurl_2 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_2");
            this.Figureurl_QQ_1 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_qq_1");
            this.Figureurl_QQ_2 = QQOAuth2AuthenticatedContext.TryGetValue(user, "figureurl_qq_2");
            this.IsYellowVip = QQOAuth2AuthenticatedContext.TryGetValue(user, "is_yellow_vip");
            this.Vip = QQOAuth2AuthenticatedContext.TryGetValue(user, "vip");
            this.YellowVipLevel = QQOAuth2AuthenticatedContext.TryGetValue(user, "yellow_vip_level");
            this.Level = QQOAuth2AuthenticatedContext.TryGetValue(user, "level");
            this.IsYellowYearVip = QQOAuth2AuthenticatedContext.TryGetValue(user, "is_yellow_year_vip");
            this.Email = Name;
        }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken jToken;
            if (!user.TryGetValue(propertyName, out jToken))
            {
                return null;
            }
            return jToken.ToString();
        }

        private static string TryGetValue(JObject user, string propertyName, string subProperty)
        {
            JToken jToken;
            if (user.TryGetValue(propertyName, out jToken))
            {
                JObject jObject = JObject.Parse(jToken.ToString());
                if (jObject != null && jObject.TryGetValue(subProperty, out jToken))
                {
                    return jToken.ToString();
                }
            }
            return null;
        }

        private static string TryGetFirstValue(JObject user, string propertyName, string subProperty)
        {
            JToken jToken;
            if (user.TryGetValue(propertyName, out jToken))
            {
                JArray jArray = JArray.Parse(jToken.ToString());
                if (jArray != null && jArray.Count() > 0)
                {
                    JObject jObject = JObject.Parse(jArray.First.ToString());
                    if (jObject != null && jObject.TryGetValue(subProperty, out jToken))
                    {
                        return jToken.ToString();
                    }
                }
            }
            return null;
        }
    }
}
