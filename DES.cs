using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
//using static System.Net.WebRequestMethods;
//using static System.Runtime.InteropServices.JavaScript.JSType;

namespace DES
{
    public class DES
    {
        // 初始置换表
        private static readonly int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        // 逆置换表
        private static readonly int[] IP_Inverse = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25
        };
        // S盒
        private static readonly int[,,] S_Box =
        {
            //S1
            {
                { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
            },
            //S2
            {
                { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
            },
            //S3
            {
                { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
            },
            //S4
            {
                { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
            },
            //S5
            {
                { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
            },
            //S6
            {
                { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
            },
            //S7
            {
                { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
                { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
                { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
                { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
            },
            //S8
            {
                { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
            }
        };
        // P盒，定义了S盒替换后数据的重新排列
        private static readonly int[] P_Box = {
            16,  7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26,  5, 18, 31, 10,
             2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
        };
        //选择扩展置换E
        private static readonly int[] Expansion = {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        };
        // 密钥置换表1
        private static readonly int[] PC_1 ={
            57, 49, 41, 33, 25, 17,  9,
             1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
        };

        private static readonly int[] PC_2 = {
            14, 17, 11, 24,  1,  5,
             3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        // 子密钥生成算法中每轮的左移位数
        private static readonly int[] Shift_Table = {
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
        };
        //BitArray循环左移
        public static BitArray LeftCircularShift(BitArray bitArray, int shiftCount)
        {
            int length = bitArray.Length;
            BitArray shiftedArray = new BitArray(length);
            // 规范化移位数，防止移位数超过 BitArray 的长度
            shiftCount = shiftCount % length;
            // 循环遍历每个位，进行左移和循环
            for (int i = 0; i < length; i++)
            {
                // 计算左移后的位置，使用减法以实现左移效果
                int newIndex = (i - shiftCount + length) % length;
                shiftedArray[newIndex] = bitArray[i];
            }
            return shiftedArray;
        }
        // BitArray大端序存储字节
        public static BitArray ConvertToBigEndianBitArray(byte[] bytes)
        {
            BitArray bitArray = new BitArray(bytes);
            BitArray reversedArray = new BitArray(bitArray.Length);
            // 翻转每个字节中的位顺序
            for (int i = 0; i < bitArray.Length; i++)
            {
                int byteIndex = i / 8 * 8; // 计算当前位属于哪个字节
                int bitIndexInByte = 7 - (i % 8); // 翻转字节内的位顺序
                reversedArray[i] = bitArray[byteIndex + bitIndexInByte];
            }
            return reversedArray;
        }
        //将大端序存储的BitAray转换为16进制的字节数组
        public static byte[] ConvertBitArrayToHex(BitArray bitArray)
        {
            int length = bitArray.Length;
            int numBytes = (length + 7) / 8; // 计算字节数，确保不足8位时补充完整
            byte[] bytes = new byte[numBytes];
            // 遍历 BitArray，每8位组合成一个字节，按照大端序存储
            for (int i = 0; i < length; i++)
            {
                int byteIndex = i / 8;
                int bitIndexInByte = 7 - (i % 8); // 大端序：高位在前（MSB），低位在后
                if (bitArray[i])
                {
                    bytes[byteIndex] |= (byte)(1 << bitIndexInByte);
                }
            }
            return bytes;
        }
        // 加密方法，接受明文和密钥，返回加密后的密文
        public static string Encrypt(string plainText, string key, string mode, bool addPadding = true)
        {
            byte[] plainBytes;
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            // 初始化向量（IV），用于 CBC 模式
            byte[] iv = new byte[8];
            if (mode == "CBC")
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv);
                }
            }
            // 如果需要填充
            if (addPadding)
            {
                plainBytes = Encoding.UTF8.GetBytes(Padding_PKCS7(plainText));
            }
            // 如果不需要填充
            else
            {
                byte[] inputBytes = Convert.FromBase64String(plainText);
                plainBytes= new byte[inputBytes.Length - iv.Length];
                Buffer.BlockCopy(inputBytes, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(inputBytes, iv.Length, plainBytes, 0, inputBytes.Length-iv.Length);
            }

            // 将密钥转换为 BitArray
            BitArray keyBits = ConvertToBigEndianBitArray(keyBytes);

            // 分组加密
            List<byte> cipherBytesList = new List<byte>();
            byte[] previousCipherBlock = iv;

            for (int i = 0; i < plainBytes.Length; i += 8)
            {
                // 取出每组 8 字节（64 位）
                byte[] block = new byte[8];
                Array.Copy(plainBytes, i, block, 0, 8);

                if (mode == "CBC")
                {
                    // CBC 模式下，当前明文块与前一密文块异或
                    for (int j = 0; j < 8; j++)
                    {
                        block[j] ^= previousCipherBlock[j];
                    }
                }

                // 将每组数据转换为 BitArray
                BitArray blockBits = ConvertToBigEndianBitArray(block);

                // 执行 DES 加密
                BitArray cipherBits = DES_Encrypt(blockBits, keyBits);

                // 将加密后的 BitArray 转换为字节数组
                byte[] cipherBlock = ConvertBitArrayToHex(cipherBits);

                // 将加密后的字节数组添加到结果列表中
                cipherBytesList.AddRange(cipherBlock);

                // 更新前一密文块
                if (mode == "CBC")
                {
                    previousCipherBlock = cipherBlock;
                }
            }

            // 将加密后的字节数组转换为 16 进制字符串
            string cipherText = BitConverter.ToString(cipherBytesList.ToArray()).Replace("-", "");

            // 如果是 CBC 模式，返回 IV + 密文
            if (mode == "CBC")
            {
                string ivHex = BitConverter.ToString(iv).Replace("-", "");
                return ivHex + cipherText;
            }

            return cipherText;
        }
        // 解密方法，接受密文和密钥，返回解密后的明文
        public static string Decrypt(string cipherText, string key, string mode, bool removePadding = true)
        {
            // 将密文转换为字节数组
            byte[] cipherBytes = Enumerable.Range(0, cipherText.Length)
                                           .Where(x => x % 2 == 0)
                                           .Select(x => Convert.ToByte(cipherText.Substring(x, 2), 16))
                                           .ToArray();
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            // 将密钥转换为 BitArray
            BitArray keyBits = ConvertToBigEndianBitArray(keyBytes);

            // 初始化向量（IV），用于 CBC 模式
            byte[] iv = new byte[8]; // 64 位（8 字节）
            int offset = 0;
            if (mode == "CBC")
            {
                Array.Copy(cipherBytes, iv, 8);
                offset = 8;
            }

            // 分组解密
            List<byte> plainBytesList = new List<byte>();
            byte[] previousCipherBlock = iv;

            for (int i = offset; i < cipherBytes.Length; i += 8)
            {
                // 取出每组 8 字节（64 位）
                byte[] block = new byte[8];
                Array.Copy(cipherBytes, i, block, 0, 8);

                // 将每组数据转换为 BitArray
                BitArray blockBits = ConvertToBigEndianBitArray(block);

                // 执行 DES 解密
                BitArray plainBits = DES_Decrypt(blockBits, keyBits);

                // 将解密后的 BitArray 转换为字节数组
                byte[] plainBlock = ConvertBitArrayToHex(plainBits);

                if (mode == "CBC")
                {
                    // CBC 模式下，当前解密块与前一密文块异或
                    for (int j = 0; j < 8; j++)
                    {
                        plainBlock[j] ^= previousCipherBlock[j];
                    }
                    previousCipherBlock = block;
                }

                // 将解密后的字节数组添加到结果列表中
                plainBytesList.AddRange(plainBlock);
            }

            // 将解密后的字节数组转换为字符串
            byte[] plainBytes = plainBytesList.ToArray();

            if (removePadding)
            {
                // 将字节数组转换为 UTF-8 字符串并移除填充
                string plainText = Encoding.UTF8.GetString(plainBytes);
                plainText = RemovePadding_PKCS7(plainText);
                return plainText;
            }
            else
            {
                // 将 IV 和解密后的字节数组拼接
                byte[] result = new byte[iv.Length + plainBytes.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(plainBytes, 0, result, iv.Length, plainBytes.Length);

                // 将拼接后的字节数组转换为 Base64 编码并返回
                return Convert.ToBase64String(result);
            }
        }
        // 3DES加密
        public static string Encrypt_3DES(string plainText, string key, string mode)
        {
            if (key.Length != 24)
            {
                throw new ArgumentException("Key length must be 24 characters (192 bits) for 3DES.");
            }

            // 将key分为3个8位密钥
            string[] key_3DES = { key.Substring(0, 8), key.Substring(8, 8), key.Substring(16, 8) };

            // 依次进行加密操作
            string encrypted = Encrypt(plainText, key_3DES[0], mode);
            string decrypted = Decrypt(encrypted, key_3DES[1], mode, false);
            return Encrypt(decrypted, key_3DES[2], mode, false);
        }
        // 3DES解密
        public static string Decrypt_3DES(string cipherText, string key, string mode)
        {
            if (key.Length != 24)
            {
                throw new ArgumentException("Key length must be 24 characters (192 bits) for 3DES.");
            }

            // 将key分为3个8位密钥
            string[] key_3DES = { key.Substring(0, 8), key.Substring(8, 8), key.Substring(16, 8) };

            // 依次进行解密操作
            string decrypted = Decrypt(cipherText, key_3DES[2], mode, false);
            string encrypted = Encrypt(decrypted, key_3DES[1], mode, false);
            return Decrypt(encrypted, key_3DES[0], mode);
        }


        // DES加密的核心方法，执行初始置换IP，16轮迭代变换和逆置换IP-1
        public static BitArray DES_Encrypt(BitArray data, BitArray key)
        {
            // 执行初始置换IP
            data = Permutation(data, IP, 64);
            // 生成16个子密钥
            BitArray[] subKeys = new BitArray[16];
            subKeys = GenerateSubKeys(key);
            // 调用轮函数处理数据
            data = RoundFunction(data, subKeys);
            // 执行逆置换IP-1
            data = Permutation(data, IP_Inverse, 64);
            // 返回加密后的数据
            return data;
        }
        // DES解密的核心方法
        public static BitArray DES_Decrypt(BitArray data, BitArray key)
        {
            // 执行初始置换IP
            data = Permutation(data, IP, 64);
            // 生成16个子密钥
            BitArray[] subKeys = GenerateSubKeys(key);
            // 翻转子密钥数组的顺序
            Array.Reverse(subKeys);
            // 调用轮函数处理数据
            data = RoundFunction(data, subKeys);
            // 执行逆置换IP-1
            data = Permutation(data, IP_Inverse, 64);
            // 返回解密后的数据
            return data;
        }
        // 置换函数
        private static BitArray Permutation(BitArray data, int[] table, int permutedLength)
        {
            BitArray permutedData = new BitArray(permutedLength);
            // 遍历IP表按照置换顺序填充新数组
            for (int i = 0; i < table.Length; i++)
            {
                int pos = table[i] - 1;
                permutedData[i] = data[pos];
            }
            return permutedData;
        }
        // 子密钥生成
        private static BitArray[] GenerateSubKeys(BitArray key)
        {
            BitArray permutedkey = Permutation(key, PC_1, 56);
            BitArray[] subKeys = new BitArray[16];
            // 56位的密钥分成两部分各28位
            BitArray key_L = new BitArray(28);
            BitArray key_R = new BitArray(28);
            for (int i = 0; i < 28; i++)
            {
                key_L[i] = key[i];
                key_R[i] = key[i + 28];
            }
            for (int i = 0; i < 16; i++)
            {
                subKeys[i] = new BitArray(48);
                key_L = LeftCircularShift(key_L, Shift_Table[i]);
                key_R = LeftCircularShift(key_R, Shift_Table[i]);
                BitArray tempKey = new BitArray(56);
                for (int j = 0; j < 28; j++)
                {
                    tempKey[j] = key_L[j];
                    tempKey[j + 28] = key_R[j];
                }
                subKeys[i] = Permutation(tempKey, PC_2, 48);
            }
            return subKeys;
        }
        // 轮函数，执行扩展、S盒代换和P盒置换等步骤
        private static BitArray RoundFunction(BitArray data, BitArray[] subKeys)
        {
            // 在这里实现轮函数，包括扩展、S盒代换和P盒置换等
            BitArray data_L = new BitArray(32);
            BitArray data_R = new BitArray(32);
            for (int i = 0; i < 32; i++)
            {
                data_L[i] = data[i];
                data_R[i] = data[i + 32];
            }
            for (int i = 0; i < 16; i++)
            {
                BitArray data_R_copy = data_R;
                // 选择扩展运算E
                data_R = Permutation(data_R, Expansion, 48);
                // 与子密钥异或
                data_R = data_R.Xor(subKeys[i]);
                // 选择压缩运算S
                BitArray temp = new BitArray(32);
                for (int j = 0; j < 8; j++)
                {
                    int row, col;
                    row = (data_R.Get(j * 6) ? 1 : 0) * 2 + (data_R.Get(j * 6 + 5) ? 1 : 0) * 1;
                    col = (data_R.Get(j * 6 + 1) ? 1 : 0) * 8 + (data_R.Get(j * 6 + 2) ? 1 : 0) * 4 +
                        (data_R.Get(j * 6 + 3) ? 1 : 0) * 2 + (data_R.Get(j * 6 + 4) ? 1 : 0) * 1;
                    int S_data = S_Box[j, row, col];
                    for (int k = 0; k < 4; k++)
                    {
                        temp[j * 4 + k] = (S_data & (1 << (3 - k))) != 0;
                    }
                }
                // 置换运算P
                data_R = Permutation(temp, P_Box, 32);
                // R与L异或
                data_R = data_R.Xor(data_L);
                data_L = data_R_copy;
            }
            BitArray permutedData = new BitArray(64);
            for (int i = 0; i < 32; i++)
            {
                permutedData[i] = data_R[i];
                permutedData[i + 32] = data_L[i];
            }
            return permutedData;
        }
        // PKCS7 填充方法
        public static string Padding_PKCS7(string data)
        {
            int blockSize = 8; // 块大小为8字节
            byte[] dataBytes = Encoding.UTF8.GetBytes(data); // 将字符串转换为字节数组
            int paddingSize = blockSize - (dataBytes.Length % blockSize); // 计算需要填充的字节数
            byte paddingValue = (byte)paddingSize; // 填充值为需要填充的字节数

            byte[] paddedData = new byte[dataBytes.Length + paddingSize];
            Array.Copy(dataBytes, paddedData, dataBytes.Length); // 复制原始数据到新数组

            // 填充数据
            for (int i = dataBytes.Length; i < paddedData.Length; i++)
            {
                paddedData[i] = paddingValue;
            }

            return Encoding.UTF8.GetString(paddedData); // 将填充后的字节数组转换为字符串并返回
        }
        // PKCS7 去除填充方法
        public static string RemovePadding_PKCS7(string data)
        {
            int paddingSize = data[data.Length - 1];
            return data.Substring(0, data.Length - paddingSize);
        }
    }
}
