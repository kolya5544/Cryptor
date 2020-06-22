using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace FileDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                string[] files = Directory.GetFiles(args[0], "*", SearchOption.AllDirectories);
                foreach (string file in files)
                {
                    DecryptFile(file);
                }
            }
        }

        private static void DecryptFile(string file)
        {
            if (file.EndsWith(".ENC"))
            {
                int Length = 0;
                using (var fr = File.Open(file, FileMode.Open, FileAccess.Read))
                {
                    using (var fw = File.Open(file.Substring(0, file.Length-4), FileMode.Create, FileAccess.Write))
                    {
                        byte[] secBytes = new byte[4];
                        fr.Read(secBytes, 0, 4);
                        byte[] lenBytes = new byte[8];
                        fr.Read(lenBytes, 0, 8);
                        Length = (int)BitConverter.ToInt64(lenBytes, 0);
                        byte[] Key = GenerateKey(24, BitConverter.ToInt32(secBytes, 0));
                        while (true)
                        {
                            byte[] buffer = new byte[512];
                            int tbf = 0;
                            try
                            {
                                tbf = fr.Read(buffer, 0, 512);
                            }
                            catch
                            {
                                break;
                            }
                            if (tbf != 0)
                            {
                                byte[] newByte = Decrypt(buffer, Key);
                                fw.Write(newByte, 0, 512);
                            }
                            else
                            {
                                break;
                            }
                        }
                        fw.Flush();
                    }

                }
                byte[] b = File.ReadAllBytes(file.Substring(0, file.Length-4));
                File.WriteAllBytes(file.Substring(0, file.Length-4), b.ToList().GetRange(0, Length).ToArray());
                File.Delete(file);
            }
        }

        public static byte[] GenerateKey(int len, int Secret)
        {

            Random r = new Random(Secret);
            byte[] key = new byte[len];
            for (int i = 0; i < len; i++)
            {
                key[i] = (byte)r.Next(0, 255);
            }
            return key;

        }

        public static byte[] Decrypt(byte[] Encrypted, byte[] key)
        {
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            List<byte> K = new List<byte>();
            K = key.ToList();
            while (K.Count < 24)
            {
                K.Add(0x00);
            }
            key = K.ToArray();
            tdes.Key = key;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.Zeros;
            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(Encrypted, 0, Encrypted.Length);
            tdes.Clear();
            return resultArray;
        }
    }
}
