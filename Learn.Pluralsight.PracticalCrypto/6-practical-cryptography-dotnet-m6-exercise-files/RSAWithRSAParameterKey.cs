using System.Security.Cryptography;

namespace CryptographyInDotNet
{
	public class RSAWithRSAParameterKey
	{
		//private const int KEY_SIZE = 2048;
		private const int KEY_SIZE = 4096;

		private RSAParameters _publicKey;
		private RSAParameters _privateKey;

		public void AssignNewKey()
		{
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				_publicKey = rsa.ExportParameters(false);
				_privateKey = rsa.ExportParameters(true);
			}
		}

		public byte[] EncryptData(byte[] dataToEncrypt)
		{
			byte[] cipherbytes;

			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_publicKey);

				cipherbytes = rsa.Encrypt(dataToEncrypt, true);
			}

			return cipherbytes;
		}

		public byte[] DecryptData(byte[] dataToEncrypt)
		{
			byte[] plain;

			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_privateKey);
				
				plain = rsa.Decrypt(dataToEncrypt, true);
			}

			return plain;
		}
	}
}