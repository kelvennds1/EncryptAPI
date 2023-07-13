namespace Sinqia4Devs.Utils.Cryptography
{
    public class AesRsa
    {
        private const string separator = "sQia4";
        private static string KeyPrivateAES = "S/UFjc1ftDFK5+77U1PB80v2GacokGap5yCIP2YI6tQ=";
        private static string IVPrivate = "miPr4lohZEwFeSFkowlHcg==";

        public static string Encrypt(string data, string RSAPublicKey)
        {
            AesUtility aes = new AesUtility(KeyPrivateAES);
            return Rsa.Encrypt(KeyPrivateAES, RSAPublicKey) + separator + aes.Encrypt(data, IVPrivate);
        }

        public static string Decrypt(string data, string RSAPrivateKey)
        {
            int indexSeparator = data.IndexOf(separator);
            var aesKey = data.Substring(0, indexSeparator);
            data = data.Substring(indexSeparator + separator.Length);

            var AESKey = Rsa.Decrypt(aesKey, RSAPrivateKey);

            AesUtility aes = new AesUtility(AESKey);
            return aes.Decrypt(data, IVPrivate);
        }
    }
}
