using Microsoft.Owin.Security.DataProtection;
using Owin;

namespace Taitans.Owin.Security.Aes
{
    public static class AppBuilderExtensions
    {
        public static void UseAesDataProtectionProvider(this IAppBuilder app)
        {
            app.UseAesDataProtectionProvider(null);
        }

        public static void UseAesDataProtectionProvider(this IAppBuilder app, string hostAppName)
        {
            string appName = "OwinNonameApp";
            if (app.Properties.ContainsKey("host.AppName"))
            {
                appName = app.Properties["host.AppName"].ToString();
            }
            AesDataProtectionProvider dataProtectionProvider = new AesDataProtectionProvider(appName)
            {
                Key = hostAppName
            };
            app.SetDataProtectionProvider(dataProtectionProvider);
        }
    }
}
