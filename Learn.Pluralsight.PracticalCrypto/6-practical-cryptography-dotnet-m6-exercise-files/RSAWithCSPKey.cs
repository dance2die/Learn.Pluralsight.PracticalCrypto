using System.Security.Cryptography;

namespace CryptographyInDotNet
{
	public class RsaWithCspKey
	{
		private const int KEY_SIZE = 2048;
		private const string CONTAINER_NAME = "ContainerName";

		public void AssignNewKey()
		{
			CspParameters cspParams = new CspParameters(1)
			{
				KeyContainerName = CONTAINER_NAME,
				Flags = CspProviderFlags.UseMachineKeyStore,
				ProviderName = "Microsoft Strong Cryptographic Provider"
			};

			//var rsa = new RSACryptoServiceProvider(cspParams) { PersistKeyInCsp = true };
			// ReSharper disable once ObjectCreationAsStatement
			new RSACryptoServiceProvider(cspParams) { PersistKeyInCsp = true };
		}

		public byte[] EncryptData(byte[] dataToEncrypt)
		{
			byte[] cipherbytes;

			var cspParams = new CspParameters { KeyContainerName = CONTAINER_NAME };
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE, cspParams))
			{
				cipherbytes = rsa.Encrypt(dataToEncrypt, false);
			}

			return cipherbytes;
		}

		public byte[] DecryptData(byte[] dataToDecrypt)
		{
			byte[] plain;

			var cspParams = new CspParameters { KeyContainerName = CONTAINER_NAME };
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE, cspParams))
			{
				plain = rsa.Decrypt(dataToDecrypt, false);
			}

			return plain;
		}

		public void DeleteKeyInCsp()
		{
			var cspParams = new CspParameters { KeyContainerName = CONTAINER_NAME };
			var rsa = new RSACryptoServiceProvider(cspParams) { PersistKeyInCsp = false };

			rsa.Clear();
		}
	}
}