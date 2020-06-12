using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Message_Exchange_Through_PKC_Sequel_Client
{
	sealed class TcpReceiver
	{
		private NetworkStream _stream;

		public TcpReceiver(NetworkStream stream)
		{
			_stream = stream;
			Thread receiveThread = new Thread(() => Receive(_stream));
			receiveThread.Start();
		}

		private static void Receive(NetworkStream stream)
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
	}
}
