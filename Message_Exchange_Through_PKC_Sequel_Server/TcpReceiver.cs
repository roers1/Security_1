using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Newtonsoft.Json.Linq;

namespace Message_Exchange_Through_PKC_Sequel_Server
{
	sealed class TcpReceiver
	{
		public TcpReceiver(NetworkStream stream, X509Certificate2 certificateClient, X509Certificate2 certificateServer)
		{
			Thread receiveThread = new Thread(() => Receive(stream, certificateClient, certificateServer));
			receiveThread.Start();
		}

		private static void Receive(NetworkStream stream, X509Certificate2 certificateClient,
			X509Certificate2 certificateServer)
		{
			Byte[] bytes = new Byte[4096];
			string data = null;
			try
			{
				while (true)
				{
					if (stream.DataAvailable)
					{
						int i;
						while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
						{
							// Translate data bytes to a ASCII string.
							string jsonString = Encoding.UTF8.GetString(bytes);

							JObject json = JObject.Parse(jsonString);

							byte[] encryptedData = (byte[]) json.GetValue("encryptedData");
							byte[] encryptedKey = (byte[]) json.GetValue("encryptedKey");

							string encryptedKeyString =
								Encoding.UTF8.GetString(Decrypt(encryptedKey, certificateServer));

							JObject encryptedKeyJson = JObject.Parse(encryptedKeyString);


							string message1 = DecryptStringFromBytes_Aes(encryptedData, Convert.FromBase64String(encryptedKeyJson.GetValue("myAesKey").ToString()),
								Convert.FromBase64String(encryptedKeyJson.GetValue("myAesIV").ToString()));


							JObject json1 = JObject.Parse(message1);

							string message = json1.GetValue("message").ToString();
							string signedData = json1.GetValue("hash").ToString();


							SHA256Managed sha256Managed = new SHA256Managed();
							var hashOfPlainMessage = sha256Managed.ComputeHash(Encoding.UTF8.GetBytes(message));

							var x = Verify(hashOfPlainMessage, Convert.FromBase64String(signedData), certificateClient);

							if (x)
							{
								Console.WriteLine(message);
							}
							else
							{
								Console.WriteLine("Hashes don't compare");
							}
						}
					}
				}
			}
			catch (SocketException e)
			{
				Console.WriteLine("SocketException: {0}", e);
			}
		}

		private static byte[] Decrypt(byte[] encryptedkey, X509Certificate2 certificate)
		{
			RSA privateKey = certificate.GetRSAPrivateKey();

			return privateKey.Decrypt(encryptedkey, RSAEncryptionPadding.Pkcs1);
		}

		private static bool Verify(byte[] hashOfPlainMessage, byte[] signedData, X509Certificate2 certificate)
		{
			RSA publicKey = certificate.GetRSAPublicKey();

			return publicKey.VerifyHash(hashOfPlainMessage, signedData, HashAlgorithmName.SHA256,
				RSASignaturePadding.Pkcs1);
		}

		static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
		{
			// Check arguments.
			if (cipherText == null || cipherText.Length <= 0)
				throw new ArgumentNullException("cipherText");
			if (Key == null || Key.Length <= 0)
				throw new ArgumentNullException("Key");
			if (IV == null || IV.Length <= 0)
				throw new ArgumentNullException("IV");

			// Declare the string used to hold
			// the decrypted text.
			string plaintext = null;

			// Create an Aes object
			// with the specified key and IV.
			using (Aes aesAlg = Aes.Create())
			{
				aesAlg.Key = Key;
				aesAlg.IV = IV;

				// Create a decryptor to perform the stream transform.
				ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for decryption.
				using (MemoryStream msDecrypt = new MemoryStream(cipherText))
				{
					using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader srDecrypt = new StreamReader(csDecrypt))
						{
							// Read the decrypted bytes from the decrypting stream
							// and place them in a string.
							plaintext = srDecrypt.ReadToEnd();
						}
					}
				}
			}

			return plaintext;
		}
	}
}