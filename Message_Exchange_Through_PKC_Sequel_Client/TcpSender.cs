using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Message_Exchange_Through_PKC_Sequel_Client
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
					Console.WriteLine("Enter message to send to the server: ");
					string message = Console.ReadLine();

					var data = Encoding.ASCII.GetBytes(message);

					stream.Write(data);
				}
			}
			catch (SocketException e)
			{
				Console.WriteLine("SocketException: {0}", e);
			}
		}

		private static byte[] ToByteArray(string[] input)
		{
			using (var stream = new MemoryStream())
			using (var writer = new BinaryWriter(stream, Encoding.UTF8))
			{
				var rows = input.GetLength(0);
				writer.Write(rows);
				for (int i = 0; i < rows; i++)
				{
					writer.Write(input[i]);
				}

				writer.Flush();
				return stream.ToArray();
			}
		}

		private static byte[] Sign(byte[] data, X509Certificate2 certificate)
		{
			RSA privateKey = certificate.GetRSAPrivateKey();

			return privateKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
		}

		private static string GetHash(HashAlgorithm hashAlgorithm, string input)
		{
			// Convert the input string to a byte array and compute the hash.
			byte[] data = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));

			// Create a new Stringbuilder to collect the bytes
			// and create a string.
			var sBuilder = new StringBuilder();

			// Loop through each byte of the hashed data
			// and format each one as a hexadecimal string.
			for (int i = 0; i < data.Length; i++)
			{
				sBuilder.Append(data[i].ToString("x2"));
			}

			// Return the hexadecimal string.
			return sBuilder.ToString();
		}
	}
}