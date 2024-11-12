using System;
using System.Diagnostics;
using DES;

namespace DEScipher
{
    public class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("请选择操作模式: 1. 加密 2. 解密");
            string operationMode = Console.ReadLine();

            while (operationMode != "1" && operationMode != "2")
            {
                Console.WriteLine("无效的选择！请选择操作模式: 1. 加密 2. 解密");
                operationMode = Console.ReadLine();
            }

            Console.WriteLine("请选择加密算法: 1. DES 2. 3DES");
            string algorithmChoice = Console.ReadLine();

            while (algorithmChoice != "1" && algorithmChoice != "2")
            {
                Console.WriteLine("无效的选择！请选择加密算法: 1. DES 2. 3DES");
                algorithmChoice = Console.ReadLine();
            }

            Console.WriteLine("请选择加密模式: 1. ECB 2. CBC");
            string encryptionMode = Console.ReadLine();

            while (encryptionMode != "1" && encryptionMode != "2")
            {
                Console.WriteLine("无效的选择！请选择加密模式: 1. ECB 2. CBC");
                encryptionMode = Console.ReadLine();
            }

            string mode = encryptionMode == "1" ? "ECB" : "CBC";

            string key;
            if (algorithmChoice == "1")
            {
                // DES 密钥长度检查
                Console.WriteLine("请输入8位密钥: ");
                key = Console.ReadLine();
                while (key.Length != 8)
                {
                    Console.WriteLine("密钥长度不正确！请重新输入8位密钥: ");
                    key = Console.ReadLine();
                }
            }
            else
            {
                // 3DES 密钥长度检查
                Console.WriteLine("请输入24位密钥: ");
                key = Console.ReadLine();
                while (key.Length != 24)
                {
                    Console.WriteLine("密钥长度不正确！请重新输入24位密钥: ");
                    key = Console.ReadLine();
                }
            }

            Console.WriteLine("请选择操作对象: 1. 文本 2. 文件");
            string targetChoice = Console.ReadLine();

            while (targetChoice != "1" && targetChoice != "2")
            {
                Console.WriteLine("无效的选择！请选择操作对象: 1. 文本 2. 文件");
                targetChoice = Console.ReadLine();
            }

            if (targetChoice == "1")
            {
                // 处理文本
                ProcessText(operationMode, algorithmChoice, mode, key);
            }
            else if (targetChoice == "2")
            {
                // 处理文件
                ProcessFile(operationMode, algorithmChoice, mode, key);
            }

            Console.ReadLine();
        }

        private static void ProcessText(string operationMode, string algorithmChoice, string mode, string key)
        {
            if (operationMode == "1")
            {
                // 加密模式
                Console.WriteLine("请输入明文: ");
                string plainText = Console.ReadLine();

                string cipherText;
                Stopwatch stopwatch = new Stopwatch();
                stopwatch.Start();
                if (algorithmChoice == "1")
                {
                    // 调用 DES 类的 Encrypt 方法进行加密
                    cipherText = DES.DES.Encrypt(plainText, key, mode);
                }
                else
                {
                    // 调用 DES 类的 Encrypt_3DES 方法进行加密
                    cipherText = DES.DES.Encrypt_3DES(plainText, key, mode);
                }
                stopwatch.Stop();
                TimeSpan timeSpan = stopwatch.Elapsed;
                // 输出加密后的密文
                Console.WriteLine("加密后的密文: " + cipherText);
                Console.WriteLine("加密用时: " + timeSpan.TotalMilliseconds + "ms");
            }
            else if (operationMode == "2")
            {
                // 解密模式
                Console.WriteLine("请输入密文: ");
                string cipherText = Console.ReadLine();

                string decryptedText;
                Stopwatch stopwatch = new Stopwatch();
                stopwatch.Start();
                if (algorithmChoice == "1")
                {
                    // 调用 DES 类的 Decrypt 方法进行解密
                    decryptedText = DES.DES.Decrypt(cipherText, key, mode);
                }
                else
                {
                    // 调用 DES 类的 Decrypt_3DES 方法进行解密
                    decryptedText = DES.DES.Decrypt_3DES(cipherText, key, mode);
                }
                stopwatch.Stop();
                TimeSpan timeSpan = stopwatch.Elapsed;
                // 输出解密后的明文
                Console.WriteLine("解密后的明文: " + decryptedText);
                Console.WriteLine("解密用时: " + timeSpan.TotalMilliseconds + "ms");
            }
        }

        private static void ProcessFile(string operationMode, string algorithmChoice, string mode, string key)
        {
            Console.WriteLine("请输入文件路径: ");
            string filePath = Console.ReadLine();

            if (!File.Exists(filePath))
            {
                Console.WriteLine("文件不存在！");
                return;
            }

            string fileContent = File.ReadAllText(filePath);
            string resultContent;

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            if (operationMode == "1")
            {
                // 加密模式
                if (algorithmChoice == "1")
                {
                    // 调用 DES 类的 Encrypt 方法进行加密
                    resultContent = DES.DES.Encrypt(fileContent, key, mode);
                }
                else
                {
                    // 调用 DES 类的 Encrypt_3DES 方法进行加密
                    resultContent = DES.DES.Encrypt_3DES(fileContent, key, mode);
                }
            }
            else
            {
                // 解密模式
                if (algorithmChoice == "1")
                {
                    // 调用 DES 类的 Decrypt 方法进行解密
                    resultContent = DES.DES.Decrypt(fileContent, key, mode);
                }
                else
                {
                    // 调用 DES 类的 Decrypt_3DES 方法进行解密
                    resultContent = DES.DES.Decrypt_3DES(fileContent, key, mode);
                }
            }

            stopwatch.Stop();
            TimeSpan timeSpan = stopwatch.Elapsed;

            // 输出结果到新文件
            string outputFilePath = operationMode == "1" ? filePath + "_enc.txt" : filePath + "_dec.txt";
            File.WriteAllText(outputFilePath, resultContent);

            Console.WriteLine($"操作完成，结果已保存到: {outputFilePath}");
            Console.WriteLine("操作用时: " + timeSpan.TotalMilliseconds + "ms");
        }
    }
}
