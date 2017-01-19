/** 
 * Copyright (C) 2017 langboost, golf1052
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
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Collections.Generic;
using org.whispersystems.curve25519;
using org.whispersystems.curve25519.csharp;
using System.Text;
using curve25519;

namespace Curve25519WinRT.WindowsPhone_Tests
{
    /// <summary>
    /// These tests have been ported over from curve25519-java to use the same fixed
    /// keys for unit testing. This ensures library compatibility. Function names will
    /// match those in the Java test code.
    /// </summary>
    [TestClass]
    public class JavaCompatibilityTests
    {
        private byte[] PUBLIC_KEY = new byte[] { 0x21, 0xf7, 0x34, 0x5f, 0x56, 0xd9, 0x60, 0x2f, 0x15, 0x23, 0x29, 0x8f, 0x4f, 0x6f, 0xce, 0xcb, 0x14, 0xdd, 0xe2, 0xd5, 0xb9, 0xa9, 0xb4, 0x8b, 0xca, 0x82, 0x42, 0x68, 0x14, 0x92, 0xb9, 0x20 };
        private byte[] PRIVATE_KEY = new byte[] { 0x38, 0x61, 0x1d, 0x25, 0x3b, 0xea, 0x85, 0xa2, 0x03, 0x80, 0x53, 0x43, 0xb7, 0x4a, 0x93, 0x6d, 0x3b, 0x13, 0xb9, 0xe3, 0x12, 0x14, 0x53, 0xe9, 0x74, 0x0b, 0x6b, 0x82, 0x7e, 0x33, 0x7e, 0x5d };

        private byte[] MESSAGE = new byte[] { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x2e };
        private byte[] VRF = new byte[] { 0x75, 0xad, 0x49, 0xbc, 0x95, 0x5f, 0x38, 0xdc, 0xf6, 0x5f, 0xb6, 0x72, 0x08, 0x6b, 0xd5, 0x09, 0xcb, 0x4b, 0x4c, 0x41, 0x04, 0x7d, 0xb1, 0x7e, 0xfd, 0xaf, 0xee, 0xbc, 0x33, 0x03, 0x71, 0xe6 };

        #region Test helper code
        private Curve25519 curve25519;
        private const int EXPECTED_LEN = 32;
        private static byte[] GetRandomBuffer(int expectedLen)
        {
            IBuffer randomIBuffer = CryptographicBuffer.GenerateRandom((uint)expectedLen);
            return WindowsRuntimeBufferExtensions.ToArray(randomIBuffer, 0, expectedLen);
        }
        #endregion

        [TestInitialize]
        public void Initialize()
        {
            //curve25519 = Curve25519.getInstance(Curve25519.BEST);
            curve25519 = Curve25519.getInstance(Curve25519.CSHARP);
        }

        [TestCleanup]
        public void Cleanup()
        {
            curve25519 = null;
        }

        [TestMethod]
        public void testKeyGen()
        {
            byte[] keyIn = new byte[32];
            byte[] keyOut = null;

            keyIn[0] = 123;

            for (int count = 0; count < 1000; count++)
            {
                keyOut = curve25519.generatePublicKey(keyIn);
                Array.Copy(keyOut, 0, keyIn, 0, EXPECTED_LEN);
            }

            byte[] result2 = new byte[]{
                (byte)0xa2, (byte)0x3c, (byte)0x84, (byte)0x09, (byte)0xf2,
                (byte)0x93, (byte)0xb4, (byte)0x42, (byte)0x6a, (byte)0xf5,
                (byte)0xe5, (byte)0xe7, (byte)0xca, (byte)0xee, (byte)0x22,
                (byte)0xa0, (byte)0x01, (byte)0xc7, (byte)0x9a, (byte)0xca,
                (byte)0x1a, (byte)0xf2, (byte)0xea, (byte)0xcb, (byte)0x4d,
                (byte)0xdd, (byte)0xfa, (byte)0x05, (byte)0xf8, (byte)0xbc,
                (byte)0x7f, (byte)0x37};



            List<byte> keyOutList = new List<byte>(keyOut);
            List<byte> result2List = new List<byte>(result2);
            CollectionAssert.AreEqual(result2, keyOut);
        }

        [TestMethod]
        public void testEcDh()
        {
            Curve25519Provider provider = new CSharpCurve25519Provider();
            byte[] p = new byte[32];
            byte[] q = null;
            byte[] n = new byte[32];

            p[0] = 100;
            n[0] = 100;

            n = provider.generatePrivateKey(n);

            for (int count = 0; count < 1000; count++)
            {
                q = provider.calculateAgreement(n, p);
                Array.Copy(q, 0, p, 0, 32);
                q = provider.calculateAgreement(n, p);
                Array.Copy(q, 0, n, 0, 32);
                n = provider.generatePrivateKey(n);
            }

            byte[] result = new byte[]{
                (byte)0xce, (byte)0xb4, (byte)0x4e, (byte)0xd6, (byte)0x4a,
                (byte)0xd4, (byte)0xc2, (byte)0xb5, (byte)0x43, (byte)0x9d,
                (byte)0x25, (byte)0xde, (byte)0xb1, (byte)0x10, (byte)0xa8,
                (byte)0xd7, (byte)0x2e, (byte)0xb3, (byte)0xe3, (byte)0x8e,
                (byte)0xf4, (byte)0x8a, (byte)0x42, (byte)0x73, (byte)0xb1,
                (byte)0x1b, (byte)0x4b, (byte)0x13, (byte)0x8d, (byte)0x17,
                (byte)0xf9, (byte)0x34};

            List<byte> qList = new List<byte>(q);
            List<byte> resultList = new List<byte>(result);
            CollectionAssert.AreEqual(resultList, qList);
        }

        // FIXME: There's no actual vector here.  If verifySignature is broken and always returns true,
        // this test will pass.
        [TestMethod]
        public void testSignVerify()
        {
            byte[] msg = new byte[100];
            byte[] sig_out = new byte[64];
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] random = new byte[64];

            privkey[0] = 123;

            for (int count = 0; count < 1000; count++)
            {
                privkey = curve25519.generatePrivateKey(privkey);
                pubkey = curve25519.generatePublicKey(privkey);
                sig_out = curve25519.calculateSignature(random, privkey, msg);

                Assert.IsTrue(curve25519.verifySignature(pubkey, msg, sig_out));

                Array.Copy(sig_out, 0, privkey, 0, 32);
            }
        }

        //TODO: Implement testSignVerify_Fail(), and make sure it throws an exception.

        /// <summary>
        /// Test GE Double Scalar Multiplication's slide routine
        /// </summary>
        [TestMethod]
        public void TestScalarMultSlide()
        {
            byte[] a = new byte[]
            {
                0x94, 0x51, 0x9a, 0xd2, 0xff, 0x68, 0xa5, 0xeb,
                0x87, 0x57, 0x0a, 0x21, 0x11, 0x03, 0x13, 0x4a,
                0x5f, 0x20, 0x3f, 0x96, 0x62, 0x4a, 0x1d, 0x24,
                0x57, 0xec, 0x71, 0x36, 0x26, 0x59, 0xc2, 0x0c
            };
            sbyte[] r = new sbyte[256];

            Ge_double_scalarmult.slide(r, a);

            #region test validation
            sbyte[] r_expected = new sbyte[]
            {
                0, 0, 5, 0, 0, 0, 0, 3, 0, 0, 0, 0, 5, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, -3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 11, 0, 0, 0, 0, 9, 0, 0, 0, 0, -9, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -13, 0, 0, 0, 0, -15, 0, 0, 0, 0, -13, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, -7, 0, 0, 0, 0, 0, 0, 0, 0, -7, 0, 0, 0, 0, -13, 0, 0, 0, 0, 3, 0, 0, 0, 0, -13, 0, 0, 0, 0, -13, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 3, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 0, -7, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 3, 0, 0, 0, 0, -13, 0, 0, 0, 0, 5, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, -13, 0, 0, 0, 0, 0, 1, 0, 0, 0
            };

            CollectionAssert.AreEqual(r, r_expected);
            #endregion
        }

        [TestMethod]
        public void testUniqueSignatures()
        {
            Curve25519KeyPair keys = curve25519.generateKeyPair();
            Random random = new Random();

            for (int i = 1; i <= 256; i++)
            {
                byte[] message = new byte[i];
                random.NextBytes(message);

                byte[] signature = curve25519.calculateVrfSignature(keys.getPrivateKey(), message);
                byte[] vrf = curve25519.verifyVrfSignature(keys.getPublicKey(), message, signature);

                Assert.IsFalse(curve25519.verifySignature(keys.getPublicKey(), message, signature));

                message[Math.Abs(random.Next(int.MaxValue)) % message.Length] ^= 0x01;

                try
                {
                    curve25519.verifyVrfSignature(keys.getPublicKey(), message, signature);
                    throw new InvalidOperationException("Should have failed");
                }
                catch (VrfSignatureVerificationFailedException e)
                {
                    // good
                }
            }
        }

        [TestMethod]
        public void testUniqueSignatureVector()
        {
            Curve25519KeyPair keys = new Curve25519KeyPair(PUBLIC_KEY, PRIVATE_KEY);
            byte[] signature = curve25519.calculateVrfSignature(keys.getPrivateKey(), MESSAGE);
            byte[] vrf = curve25519.verifyVrfSignature(keys.getPublicKey(), MESSAGE, signature);

            CollectionAssert.AreEqual(VRF, vrf);
        }
    }
}