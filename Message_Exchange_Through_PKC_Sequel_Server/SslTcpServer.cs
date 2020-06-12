using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Message_Exchange_Through_PKC_Sequel_Server
{
	public sealed class SslTcpServer
	{
		public static int Main(string[] args)
		{
			TcpListener _server = new TcpListener(IPAddress.Any, 12345);

			string certificateLocation = Directory.GetCurrentDirectory() + "\\certificates\\server.pfx";
			X509Certificate2 certificateServer = new X509Certificate2(certificateLocation,"secret");

			certificateLocation = Directory.GetCurrentDirectory() + "\\certificates\\client.pfx";
			X509Certificate2 certificateClient = new X509Certificate2(certificateLocation, "secret");

			_server.Start();

			TcpClient client = _server.AcceptTcpClient();
			NetworkStream stream = client.GetStream();

			TcpReceiver receiver = new TcpReceiver(stream,certificateClient,certificateServer);
			TcpSender sender = new TcpSender(stream,certificateClient,certificateServer);

			while(true){}
			return 0;
		}
	}
}