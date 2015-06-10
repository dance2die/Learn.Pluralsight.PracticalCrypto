using System.Security.Cryptography;

namespace CryptographyInDotNet
{
	public class Hmac
	{
		private const int _keySize = 32;

		public static byte[] GenerateKey()
		{
			using (var randomNumberGenerator = new RNGCryptoServiceProvider())
			{
				var randomNumber = new byte[_keySize];
				randomNumberGenerator.GetBytes(randomNumber);

				return randomNumber;
			}
		}

		public static byte[] ComputeHmacsha256(byte[] toBeHashed, byte[] key)
		{
			return ComputeHmac<HMACSHA256>(toBeHashed, key);
		}

		public static byte[] ComputeHmacsha1(byte[] toBeHashed, byte[] key)
		{
			return ComputeHmac<HMACSHA1>(toBeHashed, key);
		}

		public static byte[] ComputeHmacsha512(byte[] toBeHashed, byte[] key)
		{
			return ComputeHmac<HMACSHA512>(toBeHashed, key);
		}

		public static byte[] ComputeHmacmd5(byte[] toBeHashed, byte[] key)
		{
			return ComputeHmac<HMACMD5>(toBeHashed, key);
		}

		private static byte[] ComputeHmac<T>(byte[] toBeHashed, byte[] key) where T: HMAC
		{
			var ctor = typeof (T).GetConstructor(new[] {typeof (byte[])});
			using (var instance = ctor.Invoke(new object[] {key}) as HMAC)
			{
				return instance.ComputeHash(toBeHashed);
			}
		}

	}
}
