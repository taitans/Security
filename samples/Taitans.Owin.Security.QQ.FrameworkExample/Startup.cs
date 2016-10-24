using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Taitans.Owin.Security.QQ.FrameworkExample.Startup))]
namespace Taitans.Owin.Security.QQ.FrameworkExample
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
