using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace AssetStudio
{
    public static class SpanExtensions
    {
        [DebuggerStepThrough] public static Span<T> As<T>(this Span<byte> val) where T : struct => MemoryMarshal.Cast<byte, T>(val);
        [DebuggerStepThrough] public static Span<byte> AsBytes<T>(this Span<T> val) where T : struct => MemoryMarshal.Cast<T, byte>(val);
        [DebuggerStepThrough] public static ReadOnlySpan<T> As<T>(this ReadOnlySpan<byte> val) where T : struct => MemoryMarshal.Cast<byte, T>(val);

        [DebuggerStepThrough]
        public static Span<TTo> As<TFrom, TTo>(this Span<TFrom> val)
            where TFrom : unmanaged
            where TTo : unmanaged
            => MemoryMarshal.Cast<TFrom, TTo>(val);

        [DebuggerStepThrough]
        public static ReadOnlySpan<TTo> As<TFrom, TTo>(this ReadOnlySpan<TFrom> val)
            where TFrom : unmanaged
            where TTo : unmanaged
            => MemoryMarshal.Cast<TFrom, TTo>(val);
    }
    file class CustomRc4(Func<byte, byte> transform)
    {
        private readonly Func<byte, byte> _transform = transform;

        public void Decrypt(Span<byte> data, Span<byte> key)
        {
            if (data.Length <= 0)
                return;

            var kt = new byte[256];
            for (int i = 0; i < 256; i++)
                kt[i] = (byte)i;

            var swap = 0;
            for (int i = 0; i < 256; i++)
            {
                var a = kt[i];
                swap = (swap + a + key[i % key.Length]) & 0xff;
                kt[i] = kt[swap];
                kt[swap] = a;
            }

            byte j = 0, k = 0;
            for (int i = 0; i < data.Length; i++)
            {
                j++;
                var a = kt[j];
                k = (byte)(a + k);
                kt[j] = kt[k];
                kt[k] = a;

                var kb = kt[(byte)(a + kt[j])];
                data[i] ^= _transform(kb);
            }
        }
    }
    file static class CustomCrc32
    {
        private static readonly uint[] Lookup = new uint[256];

        static CustomCrc32()
        {
            for (uint i = 0; i < 256; i++)
            {
                var val = i;
                for (uint j = 0; j < 8; j++)
                {
                    if ((val & 1) == 0)
                        val >>= 1;
                    else
                        val = (val >> 1) ^ 0xD35E417E;
                }

                Lookup[i] = val;
            }
        }

        public static uint GetCrc32(ReadOnlySpan<byte> data)
        {
            var crc = 0xffffffffu;
            foreach (var byt in data)
            {
                crc = (Lookup[unchecked((byte)crc ^ byt)] ^ (crc >> 9)) + 0x5b;
            }

            return ~crc + 0xBE9F85C1;
        }
    }
    //Special thanks to LukeFZ#4035.
    public static class FairGuardUtils
    {
        private static void DeriveKey(ReadOnlySpan<uint> keyMaterial, Span<byte> outKey)
        {
            var keyMaterialBytes = MemoryMarshal.AsBytes(keyMaterial);

            var temp1 = 0x78DA0550u;
            var temp2 = 0x2947E56Bu;
            var key = 0xc1646153u;

            foreach (var byt in keyMaterialBytes)
            {
                key = 0x21 * key + byt;

                if ((key & 0xf) > 0xA)
                {
                    var xor = 1u;
                    if (temp2 >> 6 == 0)
                        xor = temp2 << 26 != 0 ? 1u : 0u;
                    key = (key ^ xor) - 0x2CD86315;
                }
                else if ((byte)key >> 4 == 0xf)
                {
                    var xor = 1u;
                    if (temp2 >> 9 == 0)
                        xor = temp2 << 23 != 0 ? 1u : 0u;
                    key = (key ^ xor) + (temp1 ^ 0xAB4A010B);
                }
                else if (((key >> 8) & 0xf) <= 1)
                {
                    temp1 = key ^ ((temp2 >> 3) - 0x55eeab7b);
                }
                else if (temp1 + 0x567A > 0xAB5489E3)
                {
                    temp1 = key ^ ((temp1 & 0xffff0000) >> 16);
                }
                else if ((temp1 ^ 0x738766FA) <= temp2)
                {
                    temp1 = temp2 ^ (temp1 >> 8);
                }
                else if (temp1 == 0x68F53AA6)
                {
                    if (((key + temp2) ^ 0x68F53AA6) > 0x594AF86E)
                        temp1 = 0x602B1178;
                    else
                        temp2 -= 0x760A1649;
                }
                else
                {
                    if (key <= 0x865703AF)
                        temp1 = key ^ (temp1 - 0x12B9DD92);
                    else
                        temp1 = (key - 0x564389D7) ^ temp2;

                    var xor = 1u;
                    if (temp1 >> 8 == 0)
                        xor = temp1 << 24 != 0 ? 1u : 0u;
                    key ^= xor;
                }
            }

            BitConverter.GetBytes(key).CopyTo(outKey);
        }
        public class FairGuardVersion
        {
            public byte key;
            public FairGuardV version;
            public FairGuardVersion(byte key, FairGuardV v)
            {
                this.key = key;
                this.version = v;
            }
        }
        public enum FairGuardV
        {
            v1=0,
            v2=1,
            v3=3
        }
        public static int currentVerIndex = 0;
        public static List<FairGuardVersion> versions = new List<FairGuardVersion>()
        {
            new FairGuardVersion((byte)0xB7,FairGuardV.v1),
            new FairGuardVersion((byte)0x0,FairGuardV.v2), //TODO
            new FairGuardVersion((byte)0xA6,FairGuardV.v3),
            
        };
        public static void DecryptOld(Span<byte> encData)
        {
            Logger.Info($"Attempting to decrypt block with FairGuard v1 encryption...");
            var encLength = encData.Length;

            var encDataInt = encData.As<uint>();

            var encBlock1 = (stackalloc uint[4]);
            encBlock1[0] = encDataInt[2] ^ encDataInt[5] ^ 0x3F72EAF3u;
            encBlock1[1] = encDataInt[3] ^ encDataInt[7] ^ (uint)encLength;
            encBlock1[2] = encDataInt[1] ^ encDataInt[4] ^ (uint)encLength ^ 0x753BDCAAu;
            encBlock1[3] = encDataInt[0] ^ encDataInt[6] ^ 0xE3D947D3u;

            // Surprise tool for later :)
            var encBlock2Key = (stackalloc byte[4]);
            DeriveKey(encBlock1, encBlock2Key);
            var encBlock2KeyInt = encBlock2Key.As<uint>()[0];

            var encBlock1Key = (uint)encLength ^ encBlock1[0] ^ encBlock1[1] ^ encBlock1[2] ^ encBlock1[3] ^ 0x5E8BC918u;

            var encBlockRc4 = new CustomRc4(kb => (byte)(byte.RotateLeft(kb, 1) - 0x61));
            encBlockRc4.Decrypt(encBlock1.AsBytes(), BitConverter.GetBytes(encBlock1Key));

            var crc = CustomCrc32.GetCrc32(encBlock1.AsBytes());

            for (int i = 0; i < 32; i++)
                encData[i] ^= 0xb7;

            if (encLength == 32)
                return;

            if (encLength < 0x9f)
            {
                encBlockRc4.Decrypt(encData[32..], encBlock2Key);
                return;
            }

            var keyMaterial2 = (stackalloc uint[4]);
            keyMaterial2[0] = (encBlock1[3] + 0x6F1A36D8u) ^ (crc + 0x2);
            keyMaterial2[1] = (encBlock1[2] - 0x7E9A2C76u) ^ encBlock2KeyInt;
            keyMaterial2[2] = encBlock1[0] ^ 0x840CF7D0u ^ (crc + 0x2);
            keyMaterial2[3] = (encBlock1[1] + 0x48D0E844) ^ encBlock2KeyInt;

            var keyBlockKey = (stackalloc byte[4]);
            DeriveKey(keyMaterial2, keyBlockKey);

            var encBlock2 = encData.Slice(0x20, 0x80);
            var keyBlock = encBlock2.ToArray().AsSpan();
            var keyBlockInt = keyBlock.As<uint>();

            encBlockRc4.Decrypt(keyBlock, keyBlockKey);
            encBlockRc4.Decrypt(encBlock2, keyMaterial2.AsBytes()[..12]);

            var keyTable2 = (stackalloc uint[9]);
            keyTable2[0] = 0x88558046u;
            keyTable2[1] = keyMaterial2[3];
            keyTable2[2] = 0x5C7782C2u;
            keyTable2[3] = 0x38922E17u;
            keyTable2[4] = keyMaterial2[0];
            keyTable2[5] = keyMaterial2[1];
            keyTable2[6] = 0x44B38670u;
            keyTable2[7] = keyMaterial2[2];
            keyTable2[8] = 0x6B07A514u;

            var encBlock3 = encData[0xa0..];
            var remainingEncSection = encLength - 0xa0;
            var remainingNonAligned = encLength - (remainingEncSection & 0xffffff80) - 0xa0;
            if (encLength >= 0x120)
            {
                const int blockSize = 0x20;
                for (int i = 0; i < remainingEncSection / 0x80; i++)
                {
                    var currentBlockSlice = encBlock3.Slice(i * blockSize * 0x4, blockSize * 0x4).As<uint>();
                    var type = keyTable2[i % 9] & 3;

                    for (int idx = 0; idx < blockSize; idx++)
                    {
                        var keyBlockVal = keyBlockInt[idx];
                        var val = type switch
                        {
                            0 => keyBlockVal ^ keyTable2[(int)(keyMaterial2[idx & 3] % 9)] ^ (uint)(blockSize - idx),
                            1 => keyBlockVal ^ keyMaterial2[(int)(keyBlockVal & 3)] ^ keyTable2[(int)(keyBlockVal % 9)],
                            2 => keyBlockVal ^ keyMaterial2[(int)(keyBlockVal & 3)] ^ (uint)idx,
                            3 => keyBlockVal ^ keyMaterial2[(int)(keyTable2[idx % 9] & 3)] ^ (uint)(blockSize - idx),
                            _ => throw new UnreachableException()
                        };

                        currentBlockSlice[idx] ^= val;
                    }
                }
            }

            if (remainingNonAligned > 0)
            {
                var totalRemainingOffset = remainingEncSection - remainingNonAligned;
                for (int i = 0; i < remainingNonAligned; i++)
                {
                    encBlock3[(int)totalRemainingOffset + i] ^= (byte)(i ^ keyBlock[i & 0x7f] ^ (byte)(keyTable2[(int)(keyMaterial2[i & 3] % 9)] % 0xff));
                }
            }
        }
        public static void Decrypt(Span<byte> bytes)
        {
            FairGuardVersion version = versions[currentVerIndex];
            Logger.Info($"Attempting to decrypt block with FairGuard encryption...");
            
            var encryptedOffset = 0;
            var encryptedSize = Math.Min(0x500, bytes.Length);


            if (encryptedSize < 0x20)
            {
                Logger.Info("block size is less that minimum, skipping...");
                return;
            }

            var encrypted = bytes.Slice(encryptedOffset, encryptedSize);
            if (version.version == FairGuardV.v1)
            {
                DecryptOld(encrypted);
                return;
            }
            var encryptedInts = MemoryMarshal.Cast<byte, int>(encrypted);

            for (int i = 0; i < 0x20; i++)
            {
                encrypted[i] ^= (byte)version.key;
            }
           
                        // old
                        /*
             var seedPart0 = (uint)(encryptedInts[2] ^ 0x1274CBEC ^ encryptedInts[6] ^ 0x3F72EAF3);
             var seedPart1 = (uint)(encryptedInts[3] ^ 0xBE482704 ^ encryptedInts[0] ^ encryptedSize);
             var seedPart2 = (uint)(encryptedInts[1] ^ encryptedSize ^ encryptedInts[5] ^ 0x753BDCAA);
             var seedPart3 = (uint)(encryptedInts[0] ^ 0x82C57E3C ^ encryptedInts[7] ^ 0xE3D947D3);
             var seedPart4 = (uint)(encryptedInts[4] ^ 0x6F2A7347 ^ encryptedInts[7] ^ 0x4736C714);
+            */
            
            var seedPart0 = (uint)(encryptedInts[2] ^ encryptedInts[6] ^ 0x226a61b9);
            var seedPart1 = (uint)(encryptedInts[3] ^ encryptedInts[0] ^ 0x7a39d018 ^ encryptedSize);
            var seedPart2 = (uint)(encryptedInts[1] ^ encryptedInts[5] ^ 0x18f6d8aa ^ encryptedSize);
            var seedPart3 = (uint)(encryptedInts[0] ^ encryptedInts[7] ^ 0xaa255fb1);
            var seedPart4 = (uint)(encryptedInts[4] ^ encryptedInts[7] ^ 0xf78dd8eb);

            var seedInts = new uint[] { seedPart0, seedPart1, seedPart2, seedPart3, seedPart4 };
            var seedBytes = MemoryMarshal.AsBytes<uint>(seedInts);

            var seed = GenerateSeed(seedBytes);
            var seedBuffer = BitConverter.GetBytes(seed);
            seed = CRC.CalculateDigest(seedBuffer, 0, (uint)seedBuffer.Length);

            var key = seedInts[0] ^ seedInts[1] ^ seedInts[2] ^ seedInts[3] ^ seedInts[4] ^ (uint)encryptedSize;
            
            RC4(seedBytes, key);
            var keySeed = CRC.CalculateDigest(seedBytes.ToArray(), 0, (uint)seedBytes.Length);
            var keySeedBytes = BitConverter.GetBytes(keySeed);
            keySeed = GenerateSeed(keySeedBytes);

            var keyPart0 = (seedInts[3] - 0x1C26B82D) ^ keySeed;
            var keyPart1 = (seedInts[2] + 0x3F72EAF3) ^ seed;
            var keyPart2 = seedInts[0] ^ 0x82C57E3C ^ keySeed;
            var keyPart3 = (seedInts[1] + 0x6F2A7347) ^ seed;
            var keyVector = new uint[] { keyPart0, keyPart1, keyPart2, keyPart3 };

            var block = encrypted[0x20..];
            if (block.Length >= 0x80)
            {
                RC4(block[..0x60], seed);
                for (int i = 0; i < 0x60; i++)
                {
                    block[i] ^= (byte)(seed ^ 0x6E);
                }

                block = block[0x60..];
                var blockSize = (encryptedSize - 0x80) / 4;
                for (int i = 0; i < 4; i++)
                {
                    var blockOffset = i * blockSize;
                    var blockKey = i switch
                    {
                        0 => 0x6142756Eu,
                        1 => 0x62496E66u,
                        2 => 0x1304B000u,
                        3 => 0x6E8E30ECu,
                        _ => throw new NotImplementedException()
                    };
                    RC4(block.Slice(blockOffset, blockSize), seed);
                    var blockInts = MemoryMarshal.Cast<byte, uint>(block[blockOffset..]);
                    for (int j = 0; j < blockSize / 4; j++)
                    {
                        blockInts[j] ^= seed ^ keyVector[i] ^ blockKey;
                    }
                }
            }
            else
            {
                RC4(block, seed);
            }
        }

        private static uint GenerateSeed(Span<byte> bytes)
        {
            var state = new uint[] { 0xC1646153, 0x78DA0550, 0x2947E56B };
            for (int i = 0; i < bytes.Length; i++)
            {
                state[0] = 0x21 * state[0] + bytes[i];
                if ((state[0] & 0xF) >= 0xB)
                {
                    state[0] = (state[0] ^ RotateIsSet(state[2], 6)) - 0x2CD86315;
                }
                else if ((state[0] & 0xF0) >> 4 > 0xE)
                {
                    state[0] = (state[1] ^ 0xAB4A010B) + (state[0] ^ RotateIsSet(state[2], 9));
                }
                else if ((state[0] & 0xF00) >> 8 < 2)
                {
                    state[1] = ((state[2] >> 3) - 0x55EEAB7B) ^ state[0];
                }
                else if (state[1] + 0x567A >= 0xAB5489E4)
                {
                    state[1] = (state[1] >> 16) ^ state[0];
                }
                else if ((state[1] ^ 0x738766FA) <= state[2])
                {
                    state[1] = (state[1] >> 8) ^ state[2];
                }
                else if (state[1] == 0x68F53AA6)
                {
                    if ((state[1] ^ (state[0] + state[2])) > 0x594AF86E)
                    {
                        state[1] -= 0x8CA292E;
                    }
                    else
                    {
                        state[2] -= 0x760A1649;
                    }
                }
                else
                {
                    if (state[0] > 0x865703AF)
                    {
                        state[1] = state[2] ^ (state[0] - 0x564389D7);
                    }
                    else
                    {
                        state[1] = (state[1] - 0x12B9DD92) ^ state[0];
                    }

                    state[0] ^= RotateIsSet(state[1], 8);
                }
            }

            return state[0];
        }

        private static uint RotateIsSet(uint value, int count) => (((value >> count) != 0) || ((value << (32 - count))) != 0) ? 1u : 0u;

        public class CRC
        {
            private static readonly uint[] Table;

            static CRC()
            {
                Table = new uint[256];
                const uint kPoly = 0xD35E417E;
                for (uint i = 0; i < 256; i++)
                {
                    uint r = i;
                    for (int j = 0; j < 8; j++)
                    {
                        if ((r & 1) != 0)
                            r = (r >> 1) ^ kPoly;
                        else
                            r >>= 1;
                    }
                    Table[i] = r;
                }
            }

            uint _value = 0xFFFFFFFF;

            public void Update(byte[] data, uint offset, uint size)
            {
                for (uint i = 0; i < size; i++)
                    _value = (Table[(byte)_value ^ data[offset + i]] ^ (_value >> 9)) + 0x5B;
            }

            public uint GetDigest() { return ~_value - 0x41607A3D; }

            public static uint CalculateDigest(byte[] data, uint offset, uint size)
            {
                var crc = new CRC();
                crc.Update(data, offset, size);
                return crc.GetDigest();
            }
        }

        public static void RC4(Span<byte> data, uint key) => RC4(data, BitConverter.GetBytes(key));

        public static void RC4(Span<byte> data, byte[] key)
        {
            int[] S = new int[0x100];
            for (int _ = 0; _ < 0x100; _++)
            {
                S[_] = _;
            }

            int[] T = new int[0x100];

            if (key.Length == 0x100)
            {
                Buffer.BlockCopy(key, 0, T, 0, key.Length);
            }
            else
            {
                for (int _ = 0; _ < 0x100; _++)
                {
                    T[_] = key[_ % key.Length];
                }
            }

            int i = 0;
            int j = 0;
            for (i = 0; i < 0x100; i++)
            {
                j = (j + S[i] + T[i]) % 0x100;

                (S[j], S[i]) = (S[i], S[j]);
            }

            i = j = 0;
            for (int iteration = 0; iteration < data.Length; iteration++)
            {
                i = (i + 1) % 0x100;
                j = (j + S[i]) % 0x100;

                (S[j], S[i]) = (S[i], S[j]);
                var K = (uint)S[(S[j] + S[i]) % 0x100];

                var k = (byte)(K << 1) | (K >> 7);
                data[iteration] ^= (byte)(k - 0x61);
            }
        }
    }
}