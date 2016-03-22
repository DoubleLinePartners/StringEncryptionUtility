using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net;

namespace EncryptDecrypt
{
    internal class Program
    {
        /// <summary>
        /// Main
        /// </summary>
        private static void Main(string[] args)
        {
            if ((args.Length == 3) && args[0].Equals("k"))
            {
                // Generate a new key pair
                Keys(args[1], args[2]);
            }
            else if ((args.Length == 4) && args[0].Equals("e"))
            {
                // Encrypt a file
                Encrypt(args[1], args[2], args[3]);
            }
            else if ((args.Length == 4) && args[0].Equals("d"))
            {
                // Decrypt a file
                Decrypt(args[1], args[2], args[3]);
            }
            else {
                // Show usage
                Console.WriteLine("Usage:");
                Console.WriteLine("   – New key pair: EncryptDecrypt k public_key_file private_key_file");
                Console.WriteLine("   – Encrypt: EncryptDecrypt e public_key_file plain_file encrypted_file");
                Console.WriteLine("   – Decrypt: EncryptDecrypt d private_key_file encrypted_file plain_file");
            }
            // Exit
            Console.WriteLine("\n << Press any key to continue >>");
            Console.ReadKey();
        } // Main

        /// <summary>
        /// Generate a new key pair
        /// </summary>
        private static void Keys(string publicKeyFileName, string privateKeyFileName)
        {
            // Variables
            StreamWriter publicKeyFile = null;
            StreamWriter privateKeyFile = null;

            try
            {
                // Create a new key pair on target CSP
                var cspParams = new CspParameters
                {
                    ProviderType = 1,
                    Flags = CspProviderFlags.UseArchivableKey,
                    KeyNumber = (int)KeyNumber.Exchange
                };
                // PROV_RSA_FULL
                //cspParams.ProviderName; // CSP name
                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Export public key
                var publicKey = rsaProvider.ToXmlString(false);

                // Write public key to file
                publicKeyFile = File.CreateText(publicKeyFileName);
                publicKeyFile.Write(publicKey);

                // Export private/public key pair
                var privateKey = rsaProvider.ToXmlString(true);

                // Write private/public key pair to file
                privateKeyFile = File.CreateText(privateKeyFileName);
                privateKeyFile.Write(privateKey);
            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception generating a new key pair!More info:");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                // Do some clean up if needed
                publicKeyFile?.Close();
                privateKeyFile?.Close();
            }
        } // Keys

        /// <summary>
        /// Encrypt a file
        /// </summary>
        private static void Encrypt(string publicKeyFileName, string plainFileName, string encryptedFileName)
        {
            // Variables
            StreamReader publicKeyFile = null;
            StreamReader plainFile = null;
            FileStream encryptedFile = null;

            try
            {
                // Select target CSP
                var cspParams = new CspParameters { ProviderType = 1 }; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name
                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Read public key from file
                publicKeyFile = File.OpenText(publicKeyFileName);
                var publicKeyText = publicKeyFile.ReadToEnd();

                // Import public key
                rsaProvider.FromXmlString(publicKeyText);

                // Read plain text from file
                plainFile = File.OpenText(plainFileName);
                var plainText = plainFile.ReadToEnd();

                // Encrypt plain text
                var plainBytes = Encoding.UTF8.GetBytes(plainText);
                var encryptedBytes = rsaProvider.Encrypt(plainBytes, false);

                // Base64 encode text
                var base64Chars = new char[encryptedBytes.Length * 2];
                var charArrayLength = Convert.ToBase64CharArray(encryptedBytes, 0, encryptedBytes.Length, base64Chars, 0);
                var base64Bytes = Encoding.UTF8.GetBytes(base64Chars, 0, charArrayLength);

                // URL encode
                var urlEncodeBytes = WebUtility.UrlEncodeToBytes(base64Bytes, 0, base64Bytes.Length);

                // Write encrypted text to file
                encryptedFile = File.Create(encryptedFileName);
                encryptedFile.Write(urlEncodeBytes, 0, urlEncodeBytes.Length);
            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception encrypting file!More info:");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                // Do some clean up if needed
                publicKeyFile?.Close();
                plainFile?.Close();
                encryptedFile?.Close();
            }
        } // Encrypt

        /// <summary>
        /// Decrypt a file
        /// </summary>
        public static void Decrypt(string privateKeyFileName, string encryptedFileName, string plainFileName)
        {
            // Variables
            StreamReader privateKeyFile = null;
            FileStream encryptedFile = null;
            StreamWriter plainFile = null;

            try
            {
                // Select target CSP
                var cspParams = new CspParameters { ProviderType = 1 }; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name
                var rsaProvider = new RSACryptoServiceProvider(cspParams);

                // Read private/public key pair from file
                privateKeyFile = File.OpenText(privateKeyFileName);
                var privateKeyText = privateKeyFile.ReadToEnd();

                // Import private/public key pair
                rsaProvider.FromXmlString(privateKeyText);

                // Read encrypted text from file
                encryptedFile = File.OpenRead(encryptedFileName);

                var urlEncodeBytes = new byte[encryptedFile.Length];
                encryptedFile.Read(urlEncodeBytes, 0, (int)encryptedFile.Length);

                // url decode bytes
                var base64Bytes = WebUtility.UrlDecodeToBytes(urlEncodeBytes, 0, urlEncodeBytes.Length)?? new byte[0];

                // convert base64 to encrypted
                var base64Chars = Encoding.UTF8.GetChars(base64Bytes);
                var encryptedBytes = Convert.FromBase64CharArray(base64Chars, 0, base64Chars.Length);

                // Decrypt text
                var plainBytes = rsaProvider.Decrypt(encryptedBytes, false);

                // Write decrypted text to file
                plainFile = File.CreateText(plainFileName);
                var plainText = Encoding.UTF8.GetString(plainBytes);
                plainFile.Write(plainText);
            }
            catch (Exception ex)
            {
                // Any errors? Show them
                Console.WriteLine("Exception decrypting file!More info:");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                // Do some clean up if needed
                privateKeyFile?.Close();
                encryptedFile?.Close();
                plainFile?.Close();
            }
        } // Decrypt
    }
}