using System;
using System.Security.Cryptography;

namespace CryptographyInDotNet
{
	public class HashData
	{
		public static byte[] ComputeHashSha1(byte[] toBeHashed)
		{
			return ComputeHash<SHA1>(toBeHashed);
		}

		public static byte[] ComputeHashSha256(byte[] toBeHashed)
		{
			return ComputeHash<SHA256>(toBeHashed);
		}

		public static byte[] ComputeHashSha512(byte[] toBeHashed)
		{
			return ComputeHash<SHA512>(toBeHashed);
		}

		public static byte[] ComputeHashMd5(byte[] toBeHashed)
		{
			return ComputeHash<MD5>(toBeHashed);
		}

		private static byte[] ComputeHash<T>(byte[] toBeHashed) where T: HashAlgorithm
		{
			Type t = typeof (T);
			using (var hasher = t.GetMethod("Create", new Type[0]).Invoke(null, null) as HashAlgorithm)
			{
				if (hasher != null) return hasher.ComputeHash(toBeHashed);
			}
			throw new ArgumentException("Could not convert type to HashAlgorithm");
		}
	}
}
