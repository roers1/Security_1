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
			Byte[] bytes = new Byte[256];
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
							data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);
							Console.WriteLine("Received: {0}", data);
						}
					}
				}
			}
			catch (SocketException e)
			{
				Console.WriteLine("SocketException: {0}", e);
			}
		}

		private static string Decrypt(byte[] data, X509Certificate2 certificate)
		{
			RSA publicKey = certificate.GetRSAPublicKey();

			var decryptedData = publicKey.Decrypt(data, RSAEncryptionPadding.Pkcs1);

			return Encoding.ASCII.GetString(decryptedData);
		}

		private static string[] FromByteArray(byte[] input)
		{
			using (var stream = new MemoryStream(input))
			using (var reader = new BinaryReader(stream, Encoding.UTF8))
			{
				var rows = reader.ReadInt32();
				var result = new string[rows];
				for (int i = 0; i < rows; i++)
				{
					result[i] = reader.ReadString();
				}

				return result;
			}
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

		private static bool VerifyHash(HashAlgorithm hashAlgorithm, string input, string hash)
		{
			// Hash the input.
			var hashOfInput = GetHash(hashAlgorithm, input);

			// Create a StringComparer an compare the hashes.
			StringComparer comparer = StringComparer.OrdinalIgnoreCase;

			return comparer.Compare(hashOfInput, hash) == 0;
		}
	}
}