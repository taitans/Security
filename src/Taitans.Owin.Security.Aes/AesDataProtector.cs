using Microsoft.Owin.Security.DataProtection;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Linq;
using System.Security;

namespace Taitans.Owin.Security.Aes
{
    internal class AesDataProtector : IDataProtector
    {
        private readonly byte[] key;

        public AesDataProtector(string key)
        {
            using (SHA256Managed sHA256Managed = new SHA256Managed())
            {
                this.key = sHA256Managed.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }

        public byte[] Protect(byte[] userData)
        {
            byte[] buffer;
            using (SHA256Managed sHA256Managed = new SHA256Managed())
            {
                buffer = sHA256Managed.ComputeHash(userData);
            }
            byte[] result;
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.Key = this.key;
                aesManaged.GenerateIV();
                using (ICryptoTransform cryptoTransform = aesManaged.CreateEncryptor(aesManaged.Key, aesManaged.IV))
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        memoryStream.Write(aesManaged.IV, 0, 16);
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                        {
                            using (BinaryWriter binaryWriter = new BinaryWriter(cryptoStream))
                            {
                                binaryWriter.Write(buffer);
                                binaryWriter.Write(userData.Length);
                                binaryWriter.Write(userData);
                            }
                        }
                        byte[] array = memoryStream.ToArray();
                        result = array;
                    }
                }
            }
            return result;
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            byte[] result;
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.Key = this.key;
                using (MemoryStream memoryStream = new MemoryStream(protectedData))
                {
                    byte[] array = new byte[16];
                    memoryStream.Read(array, 0, 16);
                    aesManaged.IV = array;
                    using (ICryptoTransform cryptoTransform = aesManaged.CreateDecryptor(aesManaged.Key, aesManaged.IV))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                        {
                            using (BinaryReader binaryReader = new BinaryReader(cryptoStream))
                            {
                                byte[] second = binaryReader.ReadBytes(32);
                                int count = binaryReader.ReadInt32();
                                byte[] array2 = binaryReader.ReadBytes(count);
                                byte[] first;
                                using (SHA256Managed sHA256Managed = new SHA256Managed())
                                {
                                    first = sHA256Managed.ComputeHash(array2);
                                }
                                if (!first.SequenceEqual(second))
                                {
                                    throw new SecurityException("Signature does not match the computed hash");
                                }
                                result = array2;
                            }
                        }
                    }
                }
            }
            return result;
        }
    }
}