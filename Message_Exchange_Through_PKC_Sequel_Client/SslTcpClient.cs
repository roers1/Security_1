using System;
using System.Collections;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Message_Exchange_Through_PKC_Sequel_Client
{
	public class SslTcpClient
	{
		public static int Main(String[] args)
		{
			TcpClient _client = new TcpClient();

			string certificateLocation = Directory.GetCurrentDirectory() + "\\certificates\\server.pfx";
			X509Certificate2 certificateServer = new X509Certificate2(certificateLocation, "secret");

			certificateLocation = Directory.GetCurrentDirectory() + "\\certificates\\client.pfx";
			X509Certificate2 certificateClient = new X509Certificate2(certificateLocation, "secret");

			_client.Connect("HP-Envy-Ruben", 12345);

			NetworkStream stream = _client.GetStream();

			TcpReceiverClient receiver = new TcpReceiverClient(stream,certificateClient,certificateServer);
			TcpSenderClient sender = new TcpSenderClient(stream, certificateClient,certificateServer);

			Console.Title = "Client";

			while (true)
			{
			}

			return 0;
		}
	}
}