using System;
using System.Security.Cryptography;
using System.Text;

namespace Sinqia4Devs.Utils.Cryptography
{
    internal class AesUtility
    {
        readonly byte[] key;

        public AesUtility(string base64key)
        {
            this.key = Convert.FromBase64String(base64key);
        }

        public static string GenerateIV()
        {
            var rijndaelManaged = new RijndaelManaged();

            rijndaelManaged.GenerateIV();

            return Convert.ToBase64String(rijndaelManaged.IV);
        }

        public string Encrypt(string plainString, string base64IV)
        {
            var rijndael = new RijndaelManaged
            {
                BlockSize = 128,
                Key = key,
                IV = Convert.FromBase64String(base64IV),
            };

            var encryptor = rijndael.CreateEncryptor();

            byte[] bytes = Encoding.UTF8.GetBytes(plainString);

            return Convert.ToBase64String(encryptor.TransformFinalBlock(bytes, 0, bytes.Length));
        }

        public string Decrypt(string base64Encrypted, string base64IV)
        {
            var rijndael = new RijndaelManaged
            {
                BlockSize = 128,
                Key = key,
                IV = Convert.FromBase64String(base64IV),
            };

            var decryptor = rijndael.CreateDecryptor();

            byte[] bytes = Convert.FromBase64String(base64Encrypted);

            return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(bytes, 0, bytes.Length));
        }

        public static string GenerateNewKey()
        {
            var rijndael = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 128
            };

            rijndael.GenerateKey();

            return Convert.ToBase64String(rijndael.Key);
        }

        public string GenerateNewIv()
        {
            var rijndael = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 128
            };

            rijndael.GenerateIV();

            return Convert.ToBase64String(rijndael.IV);
        }
    }
}
