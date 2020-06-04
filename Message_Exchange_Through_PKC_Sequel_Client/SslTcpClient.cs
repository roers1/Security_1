using System;
using System.Collections;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Message_Exchange_Through_PKC_Sequel_Client
{
	public class SslTcpClient
	{
		private static Hashtable certificateErrors = new Hashtable();
		private static X509Certificate2 localCertificate2 = null;

		public static int Main(string[] args)
		{
			string serverCertificateName = "HP-Envy-Ruben";
			string machineName = "HP-Envy-Ruben";

			string certificate = Directory.GetCurrentDirectory() + "\\client.pfx";
			localCertificate2 = new X509Certificate2(certificate, "secret");

			SslTcpClient.RunClient(machineName, serverCertificateName);
			return 0;
		}

		public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain,
			SslPolicyErrors sslPolicyErrors)
		{
			if (sslPolicyErrors == SslPolicyErrors.None)
				return true;

			Console.WriteLine("Certificate error: {0}", sslPolicyErrors);


			return false;
		}

		public static void RunClient(string machineName, string serverName)
		{
			TcpClient client = new TcpClient(machineName, 8080);
			Console.WriteLine("Client connected.");

			SslStream sslStream = new SslStream(
				client.GetStream(),
				false,
				new RemoteCertificateValidationCallback(ValidateServerCertificate),
				null
			);

			try
			{
				sslStream.AuthenticateAsClient(serverName, GetX509CertificateCollection(), true);
			}
			catch (AuthenticationException e)
			{
				Console.WriteLine("Exception: {0}", e.Message);
				if (e.InnerException != null)
				{
					Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
				}

				Console.WriteLine("Authentication failed - closing the connection.");
				client.Close();
				return;
			}

			string plainMessage = "Hello from the client.";
			
			string hashedMessage = GetHash(SHA256.Create(), plainMessage);
			byte[] messsage = Encoding.UTF8.GetBytes($"{plainMessage}-{hashedMessage}<EOF>");

			sslStream.Write(messsage);
			sslStream.Flush();

			string serverMessage = ReadMessage(sslStream);
			Console.WriteLine("Server says: {0}", serverMessage);

			client.Close();
			Console.WriteLine("Client closed.");
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

			return messageData.ToString();
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

		public static X509CertificateCollection GetX509CertificateCollection()
		{
			string certificate = Directory.GetCurrentDirectory() + "\\client.pfx";
			X509Certificate certificate1 = new X509Certificate(certificate, "secret");
			X509CertificateCollection collection1 = new X509CertificateCollection
			{
				certificate1
			};
			return collection1;
		}
	}
}