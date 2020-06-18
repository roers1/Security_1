using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Microsoft.VisualBasic;
using Newtonsoft.Json.Linq;

namespace Message_Exchange_Through_PKC_Sequel_Server
{
	sealed class TcpSender
	{
		public TcpSender(NetworkStream stream, X509Certificate2 certificateClient, X509Certificate2 certificateServer)
		{
			Thread sendThread = new Thread(() => Send(stream, certificateServer, certificateClient));
			sendThread.Start();
		}

		private static void Send(NetworkStream stream, X509Certificate2 certificateServer,
			X509Certificate2 certificateClient)
		{
			try
			{
				while (true)
				{
					//Inlezen van het te verzenden bericht
					Console.WriteLine("Enter message to send to the server: ");
					string plainMessage = Console.ReadLine();

					//Hashen en signen
					byte[] plainMessageInBytes = Encoding.UTF8.GetBytes(plainMessage);
					string signedHashMessage =
						Convert.ToBase64String(SignMessage(plainMessageInBytes, certificateServer));


					//Te versturen asymetrische encryptie in een object zetten
					JObject asymmetricalEncryption = new JObject
					{
						{"message", plainMessage},
						{"hash", signedHashMessage}
					};

					byte[] encryptedData;
					byte[] encryptedKey;

					using (Aes myAes = Aes.Create())
					{
						// Encrypt the string to an array of bytes.
						encryptedData = EncryptStringToBytes_Aes(asymmetricalEncryption.ToString(), myAes.Key, myAes.IV);

						//Symmetrische sleuter in een object zetten
						JObject symmetricalKey = new JObject
						{
							{"myAesKey", Convert.ToBase64String(myAes.Key)},
							{"myAesIV", Convert.ToBase64String(myAes.IV)}
						};

						//versleutelen van de symmetrische sleutel
						encryptedKey = Encrypt(Encoding.UTF8.GetBytes(symmetricalKey.ToString()), certificateClient);
					}

					//Versleutelde asymmetrische encryptie en bijbehorende symmetrische sleutel
					JObject symmetricalEncryption = new JObject
					{
						{"encryptedData", encryptedData},
						{"encryptedKey", encryptedKey}
					};

					stream.Write(Encoding.UTF8.GetBytes(symmetricalEncryption.ToString()));
				}
			}
			catch (SocketException e)
			{
				Console.WriteLine("SocketException: {0}", e);
			}
		}

		private static byte[] Encrypt(byte[] symmetricalKey, X509Certificate2 certificate)
		{
			RSA publickey = certificate.GetRSAPublicKey();
			return publickey.Encrypt(symmetricalKey, RSAEncryptionPadding.Pkcs1);
		}

		private static byte[] SignMessage(byte[] plainMessage, X509Certificate2 certificate)
		{
			RSA privateKey = certificate.GetRSAPrivateKey();
			return privateKey.SignData(plainMessage, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}

		static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
		{
			// Check arguments.
			if (plainText == null || plainText.Length <= 0)
				throw new ArgumentNullException("plainText");
			if (Key == null || Key.Length <= 0)
				throw new ArgumentNullException("Key");
			if (IV == null || IV.Length <= 0)
				throw new ArgumentNullException("IV");
			byte[] encrypted;

			// Create an Aes object
			// with the specified key and IV.
			using (Aes aesAlg = Aes.Create())
			{
				aesAlg.Key = Key;
				aesAlg.IV = IV;

				// Create an encryptor to perform the stream transform.
				ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for encryption.
				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
						{
							//Write all data to the stream.
							swEncrypt.Write(plainText);
						}

						encrypted = msEncrypt.ToArray();
					}
				}
			}

			// Return the encrypted bytes from the memory stream.
			return encrypted;
		}
	}
}