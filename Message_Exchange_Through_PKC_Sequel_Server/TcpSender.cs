using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Message_Exchange_Through_PKC_Sequel_Server
{
	sealed class TcpSender
	{
		private NetworkStream _stream;

		public TcpSender(NetworkStream stream)
		{
			_stream = stream;
			Thread sendThread = new Thread(() => Send(stream));
			sendThread.Start();
		}

		private static void Send(NetworkStream stream)
		{
			try
			{
				while (true)
				{
					Console.WriteLine("Enter message to send to the server: ");
					string message = Console.ReadLine();

					byte[] msg = System.Text.Encoding.ASCII.GetBytes(message);

					stream.Write(msg);
				}
			}
			catch (SocketException e)
			{
				Console.WriteLine("SocketException: {0}",e);
			}
		}
	}
}