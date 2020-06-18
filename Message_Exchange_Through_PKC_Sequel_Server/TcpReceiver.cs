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
							string jsonString = Encoding.ASCII.GetString(bytes);

							JObject json = JObject.Parse(jsonString);

							string message = json.GetValue("message").ToString();
							string signedData = json.GetValue("hash").ToString();

							SHA256Managed sha256Managed = new SHA256Managed();
							var hashOfPlainMessage = sha256Managed.ComputeHash(Convert.FromBase64String(message));

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
	

		private static bool Verify(byte[] hashOfPlainMessage, byte[] signedData, X509Certificate2 certificate)
		{
			RSA publicKey = certificate.GetRSAPublicKey();

			return publicKey.VerifyHash(hashOfPlainMessage, signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}
	}
}