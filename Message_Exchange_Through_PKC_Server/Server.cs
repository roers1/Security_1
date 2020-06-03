﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Message_Exchange_Through_PKC_Server
{
	public class Server
	{
		static X509Certificate serverCertificate = null;

		public static void RunServer(string certificate)
		{
			//server certificaat inlezen
			serverCertificate = new X509Certificate(certificate,"secret");

			//server aanmaken die gaat luisteren op een ip adress voor een client
			TcpListener listener = new TcpListener(IPAddress.Any, 8080);
			listener.Start();

			while (true)
			{
				Console.WriteLine("Waiting for a client to connect...");
				TcpClient client = listener.AcceptTcpClient();
				ProcessClient(client);
			}
		}

		static void ProcessClient(TcpClient client)
		{
			//Ssl stream aanmaken door middel van de client
			SslStream sslStream = new SslStream(client.GetStream(), false);

			try
			{
				sslStream.AuthenticateAsServer(serverCertificate, clientCertificateRequired: false, checkCertificateRevocation: true);

				// Display the properties and settings for the authenticated stream.
				DisplaySecurityLevel(sslStream);
				DisplaySecurityServices(sslStream);
				DisplayCertificateInformation(sslStream);
				DisplayStreamProperties(sslStream);

				sslStream.ReadTimeout = 5000;
				sslStream.WriteTimeout = 5000;

				Console.WriteLine("Waiting for client message...");
				string messageData = ReadMessage(sslStream);
				Console.WriteLine("Received: {0}", messageData);

				// Write a message to the client.
				byte[] message = Encoding.UTF8.GetBytes("Hello from the server.<EOF>");
				Console.WriteLine("Sending hello message.");
				sslStream.Write(message);
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
				return;
			}
			finally
			{
				// The client stream will be closed with the sslStream
				// because we specified this behavior when creating
				// the sslStream.
				sslStream.Close();
				client.Close();
			}
		}

		static string ReadMessage(SslStream sslStream)
		{
			// Read the  message sent by the client.
			// The client signals the end of the message using the
			// "<EOF>" marker.
			byte[] buffer = new byte[2048];
			StringBuilder messageData = new StringBuilder();
			int bytes = -1;
			do
			{
				// Read the client's test message.
				bytes = sslStream.Read(buffer, 0, buffer.Length);

				// Use Decoder class to convert from bytes to UTF8
				// in case a character spans two buffers.
				Decoder decoder = Encoding.UTF8.GetDecoder();
				char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
				decoder.GetChars(buffer, 0, bytes, chars, 0);
				messageData.Append(chars);
				// Check for EOF or an empty message.
				if (messageData.ToString().IndexOf("<EOF>") != -1)
				{
					break;
				}
			} while (bytes != 0);

			return messageData.ToString();
		}

		static void DisplaySecurityLevel(SslStream stream)
		{
			Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
			Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
			Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm,
				stream.KeyExchangeStrength);
			Console.WriteLine("Protocol: {0}", stream.SslProtocol);
		}

		static void DisplaySecurityServices(SslStream stream)
		{
			Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
			Console.WriteLine("IsSigned: {0}", stream.IsSigned);
			Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
		}

		static void DisplayStreamProperties(SslStream stream)
		{
			Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
			Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
		}

		static void DisplayCertificateInformation(SslStream stream)
		{
			Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

			X509Certificate localCertificate = stream.LocalCertificate;
			if (stream.LocalCertificate != null)
			{
				Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
					localCertificate.Subject,
					localCertificate.GetEffectiveDateString(),
					localCertificate.GetExpirationDateString());
			}
			else
			{
				Console.WriteLine("Local certificate is null.");
			}

			// Display the properties of the client's certificate.
			X509Certificate remoteCertificate = stream.RemoteCertificate;
			if (stream.RemoteCertificate != null)
			{
				Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
					remoteCertificate.Subject,
					remoteCertificate.GetEffectiveDateString(),
					remoteCertificate.GetExpirationDateString());
			}
			else
			{
				Console.WriteLine("Remote certificate is null.");
			}
		}
	}
}