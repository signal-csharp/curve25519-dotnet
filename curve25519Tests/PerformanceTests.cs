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

using curve25519;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using org.whispersystems.curve25519;
using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace curve25519Tests
{
    [TestClass]
    public class PerformanceTests
    {
        private const int TEST_COUNT = 100;
        private const int BYTES_SIZE = 32;

        private byte[] random_bytes;

        [TestMethod]
        public void TestSecureRandom()
        {
            random_bytes = new byte[BYTES_SIZE];
            SecureRandomProvider provider = new curve25519.PCLSecureRandomProvider();
            for(int i = 0; i < TEST_COUNT; i++)
            {
                provider.nextBytes(random_bytes);
            }
        }

        [TestMethod]
        public void TestExpandContract()
        {
            SecureRandomProvider provider = new curve25519.PCLSecureRandomProvider();

            long [] limb = new long[19];
            long [] limb2 = new long [19];
            random_bytes = new byte[BYTES_SIZE];
            byte [] random_bytes2 = new byte[BYTES_SIZE];

            for (int i = 0; i < TEST_COUNT; i++)
            {
                provider.nextBytes(random_bytes);

                curve25519.donna.Curve25519Donna.fexpand(limb, random_bytes);
                curve25519.donna.Curve25519Donna.fcontract(random_bytes2, limb);
            }
        }

        /// <summary>
        /// Test the "normal" implementation (i.e. not optimized like "Donna").
        /// </summary>
        [TestMethod]
        public void TestTextBookPublicKeyGeneration()
        {
            Curve25519 curve = Curve25519.getInstance(Curve25519.CSHARP);

            byte[] private_key = new byte[BYTES_SIZE];
            byte[] public_key = new byte[BYTES_SIZE];

            for (int i = 0; i < TEST_COUNT; i++)
            {
                private_key = curve.generatePrivateKey();
                public_key = curve.generatePublicKey(private_key);
            }
        }

        /// <summary>
        /// Test the "Donna" implementation.
        /// </summary>
        [TestMethod]
        public void TestDonnaPublicKeyGeneration()
        {
            Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

            byte[] private_key = new byte[BYTES_SIZE];
            byte[] public_key = new byte[BYTES_SIZE];

            for (int i = 0; i < TEST_COUNT; i++)
            {
                private_key = curve.generatePrivateKey();
                public_key = curve.generatePublicKey(private_key);
            }
        }
    }
}
