using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Taitans.Owin.Security.QQ.Framework.Example.Startup))]
namespace Taitans.Owin.Security.QQ.Framework.Example
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
