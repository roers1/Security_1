using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Message_Exchange_Through_PKC_Sequel_Server
{
	public sealed class SslTcpServer
	{
		static X509Certificate serverCertificate = null;
		public static void RunServer(string certificate)
		{
			serverCertificate = new X509Certificate(certificate, "secret");

			TcpListener listener = new TcpListener(IPAddress.Any, 8080);
			listener.Start();
			while (true)
			{
		TcpClient client = listener.AcceptTcpClient();
				ProcessClient(client);
			}
		}

		public static bool ValidateClientCertificate(
			object sender,
			X509Certificate certificate,
			X509Chain chain,
			SslPolicyErrors sslPolicyErrors)
		{
			if (sslPolicyErrors == SslPolicyErrors.None)
				return true;

			Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

			return false;
		}

		static void ProcessClient(TcpClient client)
		{
		
			SslStream sslStream = new SslStream(
				client.GetStream(), false,
				new RemoteCertificateValidationCallback(ValidateClientCertificate),
				null);

			try
			{
				sslStream.AuthenticateAsServer(serverCertificate, clientCertificateRequired: true,
					checkCertificateRevocation: true);

				// Set timeouts for the read and write to 5 seconds.
				sslStream.ReadTimeout = 5000;
				sslStream.WriteTimeout = 5000;
				
				string messageData = ReadMessage(sslStream);

				Console.WriteLine("Received: {0}", messageData);

				// Write a message to the client.
				string plainMessage = "Hello from the server.";

				string hashedMessage = GetHash(SHA256.Create(), plainMessage);
				byte[] messsage = Encoding.UTF8.GetBytes($"{plainMessage}-{hashedMessage}<EOF>");

				sslStream.Write(messsage);
				sslStream.Flush();
			}
			catch (AuthenticationException e)
			{
				Console.WriteLine("Exception: {0}", e.Message);
				if (e.InnerException != null)
				{
					Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
				}

				Console.WriteLine("Authentication failed - closing the connection.");
				sslStream.Close();
				client.Close();
			}
			finally
			{
				sslStream.Close();
				client.Close();
			}
		}

		static string ReadMessage(SslStream sslStream)
		{
			byte[] buffer = new byte[2048];
			StringBuilder messageData = new StringBuilder();
			int bytes = -1;
			do
			{
				bytes = sslStream.Read(buffer, 0, buffer.Length);

				Decoder decoder = Encoding.UTF8.GetDecoder();
				char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
				decoder.GetChars(buffer, 0, bytes, chars, 0);
				messageData.Append(chars);

				if (messageData.ToString().IndexOf("<EOF>") != -1)
				{
					break;
				}
			} while (bytes != 0);

			messageData.Remove(messageData.Length - 5, 5);

			var messageSplit = messageData.ToString().Split('-');

			if(VerifyHash(SHA256.Create(), messageSplit[0], messageSplit[1]))
			{
				return messageSplit[0];
			}
			else
			{
				return "Message has been tampered with";
			}
		}

		private static bool VerifyHash(HashAlgorithm hashAlgorithm, string input, string hash)
		{
			var hashOfInput = GetHash(hashAlgorithm, input);

			StringComparer comparer = StringComparer.OrdinalIgnoreCase;

			return comparer.Compare(hashOfInput, hash) == 0;
		}

		private static string GetHash(HashAlgorithm hashAlgorithm, string input)
		{
			byte[] data = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));

			var sBuilder = new StringBuilder();

			for (int i = 0; i < data.Length; i++)
			{
				sBuilder.Append(data[i].ToString("x2"));
			}

			return sBuilder.ToString();
		}

		public static int Main(string[] args)
		{
			string certificate = Directory.GetCurrentDirectory() + "\\server.pfx";
			SslTcpServer.RunServer(certificate);
			return 0;
		}
	}
}