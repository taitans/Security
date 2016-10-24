using System.Web;
using System.Web.Mvc;

namespace Taitans.Owin.Security.QQ.FrameworkExample
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
