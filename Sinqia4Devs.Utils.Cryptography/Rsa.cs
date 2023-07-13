using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Sinqia4Devs.Utils.Cryptography
{
    public class Rsa
    {
        private static UnicodeEncoding _encoder = new UnicodeEncoding();

        /// <summary>
        /// Generate publuc and private keys to Cryptography
        /// </summary>
        /// <returns>key=publicParameterstr && value=privateParameterstr</returns>
        public static KeyValuePair<string, string> GenerateKeys()
        {
            string privateParameterstr;
            string publicParameterstr;

            using (var rsa = new RSACryptoServiceProvider())
            {
                var privateParameters = rsa.ExportParameters(true);
                var publicParameters = rsa.ExportParameters(false);

                privateParameterstr = rsa.ToXmlString(true);
                publicParameterstr = rsa.ToXmlString(false);
            }

            var privateKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateParameterstr));
            var publicKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicParameterstr));

            return new KeyValuePair<string, string>(publicKey, privateKey);
        }

        public static string Decrypt(string data, string keyBase64)
        {
            var base64EncodedBytes = Convert.FromBase64String(data);
            data = Encoding.UTF8.GetString(base64EncodedBytes);
            var base64PrivateEncodedBytes = Convert.FromBase64String(keyBase64);
            var privateKey = Encoding.UTF8.GetString(base64PrivateEncodedBytes);

            StringBuilder result = new StringBuilder();
            using (var rsa = new RSACryptoServiceProvider())
            {
                var dataArray1 = data.Split(new char[] { ',' }).Where(u => !string.IsNullOrEmpty(u)).ToArray();
                var lists = SplitList(dataArray1.ToList(), 128);

                foreach (var dataArray in lists)
                {
                    byte[] dataByte = new byte[dataArray.Count];
                    for (int i = 0; i < dataArray.Count; i++)
                    {
                        dataByte[i] = Convert.ToByte(dataArray[i]);
                    }
                    rsa.FromXmlString(privateKey);
                    var decryptedByte = rsa.Decrypt(dataByte, false);
                    result.Append(_encoder.GetString(decryptedByte));
                }
            }
            return result.ToString();
        }

        public static IEnumerable<List<T>> SplitList<T>(List<T> locations, int nSize = 30)
        {
            for (int i = 0; i < locations.Count; i += nSize)
            {
                yield return locations.GetRange(i, Math.Min(nSize, locations.Count - i));
            }
        }

        public static IEnumerable<string> SplitOnLength(string input, int length)
        {
            int index = 0;
            while (index < input.Length)
            {
                if (index + length < input.Length)
                {
                    yield return input.Substring(index, length);
                }
                else
                {
                    yield return input.Substring(index);
                }

                index += length;
            }
        }

        public static string Encrypt(string data, string keyBase64)
        {
            List<string> dados = new List<string>();
            byte[] plainTextBytes;
            using (var rsa = new RSACryptoServiceProvider())
            {
                var base64EncodedBytes = Convert.FromBase64String(keyBase64);   
                var clienteKey = Encoding.UTF8.GetString(base64EncodedBytes);

                Console.WriteLine(base64EncodedBytes);
                Console.WriteLine(clienteKey);
                rsa.FromXmlString(clienteKey);

                if (data.Length > 58)
                {
                    dados = SplitOnLength(data, 58).ToList();
                }
                else
                {
                    dados = new List<string>() { data };
                }

                StringBuilder sb = new StringBuilder();
                foreach (var item in dados)
                {
                    sb.Append(EncryptParts(item, rsa));
                    if (dados.IndexOf(item) < dados.Count() - 1)
                    {
                        sb.Append(",");
                    }
                }
                plainTextBytes = Encoding.UTF8.GetBytes(sb.ToString());
            }
            return Convert.ToBase64String(plainTextBytes);
        }

        private static StringBuilder EncryptParts(string data, RSACryptoServiceProvider rsa)
        {
            var dataToEncrypt = _encoder.GetBytes(data);
            var encryptedByteArray = rsa.Encrypt(dataToEncrypt, false).ToArray();
            var length = encryptedByteArray.Count();
            var item = 0;
            var sb = new StringBuilder();


            foreach (var x in encryptedByteArray)
            {
                item++;
                sb.Append(x);

                if (item < length)
                {
                    sb.Append(",");
                }
            }

            return sb;
        }
    }
}