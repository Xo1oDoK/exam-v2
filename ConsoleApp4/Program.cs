using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EncryptCardApp
{
    public class Program
    {
        static void Main(string[] args)
        {
            string currentDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string inputFilePath = Path.Combine(currentDirectory, "Card.json");
            string outputFilePath = Path.Combine(currentDirectory, "output.json");

            Console.WriteLine("Используется файл ввода: " + inputFilePath);
            Console.WriteLine("Результат будет сохранен в: " + outputFilePath);

            var processor = new CardProcessor();
            processor.ProcessFile(inputFilePath, outputFilePath);

            Console.WriteLine("Файл успешно обработан и сохранен.");
        }
    }

    public class CardProcessor
    {
        private readonly IEncryptor _encryptor;

        public CardProcessor()
        {
            _encryptor = new Encryptor();
        }

        public void ProcessFile(string inputFilePath, string outputFilePath)
        {
            string json = File.ReadAllText(inputFilePath);
            var data = JObject.Parse(json);

            foreach (var card in data["cards"])
            {
                string cvc = card["cvc"].ToString();
                string cvcHash = _encryptor.HashCVC(cvc);
                card["cvc"] = cvcHash;

                if (card is JObject cardObject)
                {
                    foreach (var property in cardObject.Properties())
                    {
                        if (property.Name != "cvc")
                        {
                            string encryptedValue = _encryptor.Encrypt(property.Value.ToString());
                            property.Value.Replace(encryptedValue);
                        }
                    }
                }
            }

            File.WriteAllText(outputFilePath, data.ToString(Formatting.Indented));
        }
    }

    public interface IEncryptor
    {
        string HashCVC(string cvc);
        string Encrypt(string plaintext);
    }

    public class Encryptor : IEncryptor
    {
        private static readonly byte[] _key = Encoding.UTF8.GetBytes("G7f9aK4pXq8Z2NvLmWjYrT1BdVQoCh5E"); // 256 бит
        private static readonly byte[] _iv = Encoding.UTF8.GetBytes("A1fG7kZpXq9W2LvM"); // 128 бит
        private static readonly byte[] _salt = Encoding.UTF8.GetBytes("ThisIsAStaticSalt"); // Соль

        public Encryptor()
        {
            Console.WriteLine("ключ для шифрования (Base64): " + Convert.ToBase64String(_key));
            Console.WriteLine("вектор IV для шифрования (Base64): " + Convert.ToBase64String(_iv));
            Console.WriteLine("соль (Base64): " + Convert.ToBase64String(_salt));
        }

        public string HashCVC(string cvc)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] saltedCvc = Combine(_salt, Encoding.UTF8.GetBytes(cvc));
                byte[] hash = sha256.ComputeHash(saltedCvc);
                return Convert.ToBase64String(hash);
            }
        }

        public string Encrypt(string plaintext)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _key;
                aes.IV = _iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var writer = new StreamWriter(cs))
                    {
                        writer.Write(plaintext);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private byte[] Combine(byte[] first, byte[] second)
        {
            byte[] combined = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, combined, 0, first.Length);
            Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
            return combined;
        }
    }
}
