/** 
 * Copyright (C) 2015 langboost
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Runtime.InteropServices.WindowsRuntime;
using curve25519.donna;

namespace curve25519Tests
{
    /// <summary>
    /// These tests cover functionality that was not a simple find/replace from Java to C#.
    /// </summary>
    [TestClass]
    public class ConversionRelatedTests
    {
        /// <summary>
        /// Basic equality / inequality sanity check
        /// </summary>
        [TestMethod]
        public void TestEquality_Ge_scalarmult_base()
        {
            byte b = 123;
            byte c = 255;
            byte d = 123;
            Assert.AreEqual<int>(0, org.whispersystems.curve25519.csharp.Ge_scalarmult_base.equal(b, c));
            Assert.AreEqual<int>(1, org.whispersystems.curve25519.csharp.Ge_scalarmult_base.equal(b, d));
        }

        /// <summary>
        /// This test checks if the standard (branch-using) way of comparing bytes is always equal with the branch-less equals method we use in curve25519.
        /// </summary>
        [TestMethod]
        public void TestEquality_Ge_scalarmult_base_both()
        {
            byte[,] test_cases = new byte[,]
            {
                {0, 0 },
                {0, 1 },
                {0, 255 },
                {255, 255 },
                {255, 0 },
                {255, 1 }
            };
            for (int i = 0; i < test_cases.GetLength(0); i++)
            {
                //branch-less equality
                int result = org.whispersystems.curve25519.csharp.Ge_scalarmult_base.equal(test_cases[i, 0], test_cases[i, 1]);

                int result2 = 0;
                if (test_cases[i, 0].CompareTo(test_cases[i, 1]) == 0)
                {
                    result2 = 1;
                }
                Assert.AreEqual<int>(result, result2);
            }
        }

        /// <summary>
        /// Verifies org.whispersystems.curve25519.csharp.Ge_scalarmult_base.negative properly detects negative numbers in a branch-less way.
        /// </summary>
        [TestMethod]
        public void TestNegative_Ge_scalarmult_base_negative()
        {
            for (sbyte b = sbyte.MinValue; b < sbyte.MaxValue; b++)
            {
                int result = org.whispersystems.curve25519.csharp.Ge_scalarmult_base.negative(b);
                bool bResult2 = b < 0;
                int result2 = 0;
                if (bResult2)
                    result2 = 1;
                Assert.AreEqual<int>(result, result2);
            }
        }

        /// <summary>
        /// Make sure Bouncy Castle's Sha512 implementation matches with other hashing functions known to provide good values.
        /// </summary>
        [TestMethod]
        public void TestSha512ProviderConsistency()
        {
            byte[] message = System.Text.Encoding.UTF8.GetBytes(
                    "abcdefghbcdefghicDEFghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
            int digestExpectedLength = 64; //for SHA 512, this is the expected length

            //The Bouncy Castle way
            org.whispersystems.curve25519.BouncyCastleDotNETSha512Provider provider = new org.whispersystems.curve25519.BouncyCastleDotNETSha512Provider();
            byte[] digestActual = new byte[digestExpectedLength];
            provider.calculateDigest(digestActual, message, message.Length);

            //The WinRT way
            HashAlgorithmProvider sha512Provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha512);
            IBuffer bMessage = WindowsRuntimeBufferExtensions.AsBuffer(message);
            IBuffer bDigest = sha512Provider.HashData(bMessage);
            byte[] digestWinRT = WindowsRuntimeBufferExtensions.ToArray(bDigest);

            //The PCLCrypto way
            PCLCrypto.IHashAlgorithmProvider sha512PCLProvider = PCLCrypto.WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(PCLCrypto.HashAlgorithm.Sha512);
            byte[] digestPCL = sha512PCLProvider.HashData(message);

            //Did we get the same value for all ways?
            CollectionAssert.AreEqual(digestWinRT, digestActual);
            CollectionAssert.AreEqual(digestPCL, digestWinRT);
        }

        [TestMethod]
        public void Test_fexpand()
        {
            long [] output = new long[19];
            byte[] input_key = new byte[] {
                0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,
                0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21
            };
            Curve25519Donna.fexpand(output, input_key);
            long[] expected = new long[] {
                0x0000000001212121,
                0x0000000000484848,
                0x0000000000242424,
                0x0000000001090909,
                0x0000000000848484,
                0x0000000001212121,
                0x0000000000909090,
                0x0000000000242424,
                0x0000000002121212,
                0x0000000000848484
            };
            for (int i = 0; i < 10; i++)
            {
                Assert.AreEqual<long>(expected[i], output[i]);
            }
        }

        [TestMethod]
        public void Test_s32_eq()
        {
            int same = Curve25519Donna.s32_eq(11, 11);
            int different = Curve25519Donna.s32_eq(13, 32);
            Assert.AreEqual<int>(0, different);
            Assert.AreEqual<int>(-1, same); //0xFFFFFFFF
        }

        [TestMethod]
        public void Test_s32_gte()
        {
            int bigger = Curve25519Donna.s32_gte(3, 2);
            int same = Curve25519Donna.s32_gte(5000, 5000);
            int less = Curve25519Donna.s32_gte(4999, 10001);

            Assert.AreEqual<int>(-1, bigger);
            Assert.AreEqual<int>(-1, same);
            Assert.AreEqual<int>(0, less);
        }

        [TestMethod]
        public void Test_fcontract()
        {
            long [] input = new long[] {
                0x0000000001212121,
                0x0000000000484848,
                0x0000000000242424,
                0x0000000001090909,
                0x0000000000848484,
                0x0000000001212121,
                0x0000000000909090,
                0x0000000000242424,
                0x0000000002121212,
                0x0000000000848484
            };
            byte[] output = new byte[32];

            Curve25519Donna.fcontract(output, input);

            byte[] expected_key = new byte[] {
                0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,
                0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21
            };

            for (int i = 0; i < 32; i++)
            {
                Assert.AreEqual<long>(expected_key[i], output[i]);
            }
        }

        [TestMethod]
        public void Test_swap_conditional()
        {
            long[] incrementing = new long[19];
            for(int i = 0; i < 19; i++)
            {
                incrementing[i] = i + 1;
            }
            long[] decrementing = new long[19];
            int j = 19;
            for (int i = 0; i < 19; i++)
            {
                decrementing[i] = j;
                j--;
            }
            long[] inc = (long[])incrementing.Clone();
            long[] dec = (long[])decrementing.Clone();

            //First-run, don't swap (iswap = 0)
            Curve25519Donna.swap_conditional(inc, dec, 0);

            for (int i = 0; i < 10; i++)
            {
                Assert.AreEqual<long>(i + 1, inc[i]);
            }
            j = 19;
            for (int i = 0; i < 10; i++)
            {
                Assert.AreEqual<long>(j, dec[i]);
                j--;
            }

            //Now swap (iswap = 1)
            Curve25519Donna.swap_conditional(inc, dec, 1);

            //First 10 places of each should have swapped, making this nicely symmetrical output
            long [] inc_expected = new long[] {
                19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
            long[] dec_expected = new long[] {
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

            for (int i = 0; i < 19; i++)
            {
                Assert.AreEqual<long>(inc_expected[i], inc[i]);
            }
            for (int i = 0; i < 19; i++)
            {
                Assert.AreEqual<long>(dec_expected[i], dec[i]);
            }
        }
    }
}
