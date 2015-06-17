using System.IO;
using System.Security.Cryptography;

namespace CryptographyInDotNet
{
	public class RsaWithXmlKey
	{
		private const int KEY_SIZE = 2048;
		//private const int KEY_SIZE = 4096;

		public void AssignNewKey(string publicKeyPath, string privateKeyPath)
		{
			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;

				if (File.Exists(privateKeyPath))
					File.Delete(privateKeyPath);

				if (File.Exists(publicKeyPath))
					File.Delete(publicKeyPath);

				var publicKeyfolder = Path.GetDirectoryName(publicKeyPath);
				var privateKeyfolder = Path.GetDirectoryName(privateKeyPath);

				if (!Directory.Exists(publicKeyfolder))
					Directory.CreateDirectory(publicKeyfolder);

				if (!Directory.Exists(privateKeyfolder))
					Directory.CreateDirectory(privateKeyfolder);

				File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
				File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));
			}
		}

		public byte[] EncryptData(string publicKeyPath, byte[] dataToEncrypt)
		{
			byte[] cipherbytes;

			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				rsa.FromXmlString(File.ReadAllText(publicKeyPath));

				cipherbytes = rsa.Encrypt(dataToEncrypt, false);
			}

			return cipherbytes;
		}

		public byte[] DecryptData(string privateKeyPath, byte[] dataToEncrypt)
		{
			byte[] plain;

			using (var rsa = new RSACryptoServiceProvider(KEY_SIZE))
			{
				rsa.PersistKeyInCsp = false;
				rsa.FromXmlString(File.ReadAllText(privateKeyPath));

				plain = rsa.Decrypt(dataToEncrypt, false);
			}

			return plain;
		}
	}
}