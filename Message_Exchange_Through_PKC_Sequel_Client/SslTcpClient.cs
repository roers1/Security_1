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
			_client.Connect("HP-Envy-Ruben", 12345);

			NetworkStream stream = _client.GetStream();

			TcpReceiver receiver = new TcpReceiver(stream);
			TcpSender sender = new TcpSender(stream);

			while (true) { }
			return 0;
		}
	}
}