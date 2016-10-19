using Microsoft.Owin.Security.DataProtection;
using System;

namespace Taitans.Owin.Security.Aes
{
    public class AesDataProtectionProvider : IDataProtectionProvider
    {
        private readonly string appName;

        public string Key { get; set; }

        public AesDataProtectionProvider(string appName)
        {
            if (appName == null)
            {
                throw new ArgumentNullException("appName");
            }
            this.appName = appName;
        }

        public IDataProtector Create(params string[] purposes)
        {
            string protectorKey = this.GetProtectorKey();
            return new AesDataProtector(protectorKey);
        }

        private string GetProtectorKey()
        {
            return (!string.IsNullOrEmpty(this.Key)) ? this.Key : this.appName;
        }
    }
}
