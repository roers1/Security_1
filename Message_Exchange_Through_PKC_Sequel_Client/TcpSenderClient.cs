using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Newtonsoft.Json.Linq;

namespace Message_Exchange_Through_PKC_Sequel_Client
{
	sealed class TcpSenderClient
	{
		public TcpSenderClient(NetworkStream stream, X509Certificate2 certificateClient, X509Certificate2 certificateServer)
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
					string message = Console.ReadLine();

					//Hashen en signen
					byte[] dataToHashAndEncrypt = Convert.FromBase64String(message);
					byte[] encryptedHashMessage = SignMessage(dataToHashAndEncrypt,certificateClient);

					var encryptionToSend = Convert.ToBase64String(encryptedHashMessage);

					JObject jsonObject = new JObject
					{
						{ "message", message },
						{ "hash", encryptionToSend }
					};

					byte[] jsonBytes = Encoding.ASCII.GetBytes(jsonObject.ToString());

					stream.Write(jsonBytes);
				}
			}
			catch (SocketException e)
			{
				Console.WriteLine("SocketException: {0}", e);
			}
		}

		private static byte[] SignMessage(byte[] plainMessage, X509Certificate2 certificate)
		{
			RSA privateKey = certificate.GetRSAPrivateKey();
			return privateKey.SignData(plainMessage, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}
	}
}