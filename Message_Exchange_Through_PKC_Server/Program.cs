using System;
using System.IO;

namespace Message_Exchange_Through_PKC_Server
{
	class Program
	{
		static void Main(string[] args)
		{
			Server.RunServer(Directory.GetCurrentDirectory() + "\\server.pfx");
			
		}
	}
}
