using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Message_Exchange_Through_PKC_Sequel_Server
{
	class HashHandler
	{

		public static string MessageToHash(string rawMessage)
		{

			// Create a SHA256   
			using (SHA256 sha256Hash = SHA256.Create())
			{
				// ComputeHash - returns byte array  
				byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawMessage));

				// Convert byte array to a string   
				StringBuilder builder = new StringBuilder();
				for (int i = 0; i < bytes.Length; i++)
				{
					builder.Append(bytes[i].ToString("x2"));
				}
				return builder.ToString();
			}
		}

		public static bool CompareHashToRaw(string hash, string message)
		{
			return MessageToHash(message).Equals(hash);
		}
	}
}
