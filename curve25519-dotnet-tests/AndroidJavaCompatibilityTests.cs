/** 
 * Copyright (C) 2017 golf1052
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
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using org.whispersystems.curve25519;
using org.whispersystems.curve25519.csharp;
using curve25519_dotnet.csharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace curve25519Tests
{
    [TestClass]
    public class AndroidJavaCompatibilityTests
    {
        #region Test helper code
        private Curve25519 curve25519;
        private const int EXPECTED_LEN = 32;
        private static void Memset(byte[] buf, byte val)
        {
            for(int i=0;i<buf.Length;i++)
            {
                buf[i] = val;
            }
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
        public void sha512_fast_test()
        {
            string sha512_input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
            byte[] sha512_correct_output = new byte[]
            {
                0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
                0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
                0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
                0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
                0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
                0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
                0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
                0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09
            };
            byte[] sha512_actual_output = new byte[64];

            BouncyCastleDotNETSha512Provider sha512provider = new BouncyCastleDotNETSha512Provider();
            sha512provider.calculateDigest(sha512_actual_output,
                Encoding.UTF8.GetBytes(sha512_input),
                sha512_input.Length);
            CollectionAssert.AreEqual(sha512_correct_output, sha512_actual_output, "SHA512 #1");

            var tmp = Encoding.UTF8.GetBytes(sha512_input);
            tmp[111] ^= 1;
            sha512_input = Encoding.UTF8.GetString(tmp);

            sha512provider.calculateDigest(sha512_actual_output,
                Encoding.UTF8.GetBytes(sha512_input),
                sha512_input.Length);
            CollectionAssert.AreNotEqual(sha512_correct_output, sha512_actual_output, "SHA512 #2");
        }

        [TestMethod]
        public void strict_fast_test()
        {
            byte[] unreduced1 = new byte[] {
                0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
            };
            byte[] unreduced2 = new byte[] {
                0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
            };
            byte[] unreduced3 = {
                0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
            };
            Assert.IsFalse(Fe_isreduced.fe_isreduced(unreduced1));
            Assert.IsFalse(Fe_isreduced.fe_isreduced(unreduced2));
            Assert.IsTrue(Fe_isreduced.fe_isreduced(unreduced3));
        }

    [TestMethod]
        public void elligator_fast_test()
        {
            byte[] elligator_correct_output = new byte[]
            {
                0x5f, 0x35, 0x20, 0x00, 0x1c, 0x6c, 0x99, 0x36,
                0xa3, 0x12, 0x06, 0xaf, 0xe7, 0xc7, 0xac, 0x22,
                0x4e, 0x88, 0x61, 0x61, 0x9b, 0xf9, 0x88, 0x72,
                0x44, 0x49, 0x15, 0x89, 0x9d, 0x95, 0xf4, 0x6e
            };

            byte[] hashtopoint_correct_output1 = new byte[]
            {
                0xce, 0x89, 0x9f, 0xb2, 0x8f, 0xf7, 0x20, 0x91,
                0x5e, 0x14, 0xf5, 0xb7, 0x99, 0x08, 0xab, 0x17,
                0xaa, 0x2e, 0xe2, 0x45, 0xb4, 0xfc, 0x2b, 0xf6,
                0x06, 0x36, 0x29, 0x40, 0xed, 0x7d, 0xe7, 0xed
            };

            byte[] hashtopoint_correct_output2 = new byte[]
            {
                0xa0, 0x35, 0xbb, 0xa9, 0x4d, 0x30, 0x55, 0x33,
                0x0d, 0xce, 0xc2, 0x7f, 0x83, 0xde, 0x79, 0xd0,
                0x89, 0x67, 0x72, 0x4c, 0x07, 0x8d, 0x68, 0x9d,
                0x61, 0x52, 0x1d, 0xf9, 0x2c, 0x5c, 0xba, 0x77
            };

            byte[] calculatev_correct_output = new byte[]
            {
                0x1b, 0x77, 0xb5, 0xa0, 0x44, 0x84, 0x7e, 0xb9,
                0x23, 0xd7, 0x93, 0x18, 0xce, 0xc2, 0xc5, 0xe2,
                0x84, 0xd5, 0x79, 0x6f, 0x65, 0x63, 0x1b, 0x60,
                0x9b, 0xf1, 0xf8, 0xce, 0x88, 0x0b, 0x50, 0x9c,
            };

            int count;

            int[] iIn = new int[10];
            int[] iOut = new int[10];
            byte[] bytes = new byte[32];
            Fe_0.fe_0(iIn);
            Fe_0.fe_0(iOut);
            for (count = 0; count < 32; count++)
            {
                bytes[count] = (byte)count;
            }
            Fe_frombytes.fe_frombytes(iIn, bytes);
            Elligator.elligator(iOut, iIn);
            Fe_tobytes.fe_tobytes(bytes, iOut);
            CollectionAssert.AreEqual(elligator_correct_output, bytes, "Elligator vector");

            /* Elligator(0) == 0 test */
            Fe_0.fe_0(iIn);
            Elligator.elligator(iOut, iIn);
            CollectionAssert.AreEqual(iOut, iIn, "Elligator(0) == 0");

            /* ge_montx_to_p3(0) -> order2 point test */
            int[] one = new int[10];
            int[] negone = new int[10];
            int[] zero = new int[10];
            Fe_1.fe_1(one);
            Fe_0.fe_0(zero);
            Fe_sub.fe_sub(negone, zero, one);
            Ge_p3 p3 = new Ge_p3();
            Ge_montx_to_p3.ge_montx_to_p3(p3, zero, 0);
            Assert.IsTrue(Fe_isequal.fe_isequal(p3.X, zero) != 0 &&
                Fe_isequal.fe_isequal(p3.Y, negone) != 0 &&
                Fe_isequal.fe_isequal(p3.Z, one) != 0 &&
                Fe_isequal.fe_isequal(p3.T, zero) != 0,
                "ge_montx_to_p3(0) == order 2 point");

            /* Hash to point vector test */
            byte[] htp = new byte[32];

            for (count = 0; count < 32; count++)
            {
                htp[count] = (byte)count;
            }

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Elligator.hash_to_point(sha512provider, p3, htp, 32);
            Ge_p3_tobytes.ge_p3_tobytes(htp, p3);
            CollectionAssert.AreEqual(hashtopoint_correct_output1, htp, "hash_to_point #1");

            for (count = 0; count < 32; count++)
            {
                htp[count] = (byte)(count + 1);
            }

            Elligator.hash_to_point(sha512provider, p3, htp, 32);
            Ge_p3_tobytes.ge_p3_tobytes(htp, p3);
            CollectionAssert.AreEqual(hashtopoint_correct_output2, htp, "hash_to_point #2");

            /* calculate_U vector test */
            Ge_p3 Bv = new Ge_p3();
            byte[] V = new byte[32];
            byte[] Vbuf = new byte[200];
            byte[] a = new byte[32];
            byte[] A = new byte[32];
            byte[] Vmsg = new byte[3];
            Vmsg[0] = 0;
            Vmsg[1] = 1;
            Vmsg[2] = 2;
            for (count = 0; count < 32; count++)
            {
                a[count] = (byte)(8 + count);
                A[count] = (byte)(9 + count);
            }
            Sc_clamp.sc_clamp(a);
            Elligator.calculate_Bv_and_V(sha512provider, Bv, V, Vbuf, a, A, Vmsg, 3);

            CollectionAssert.AreEqual(calculatev_correct_output, V, "calculate_Bv_and_V vector");
        }

        [TestMethod]
        public void curvesigs_fast_test()
        {
            byte[] signature_correct = new byte[]
            {
                0xcf, 0x87, 0x3d, 0x03, 0x79, 0xac, 0x20, 0xe8,
                0x89, 0x3e, 0x55, 0x67, 0xee, 0x0f, 0x89, 0x51,
                0xf8, 0xdb, 0x84, 0x0d, 0x26, 0xb2, 0x43, 0xb4,
                0x63, 0x52, 0x66, 0x89, 0xd0, 0x1c, 0xa7, 0x18,
                0xac, 0x18, 0x9f, 0xb1, 0x67, 0x85, 0x74, 0xeb,
                0xdd, 0xe5, 0x69, 0x33, 0x06, 0x59, 0x44, 0x8b,
                0x0b, 0xd6, 0xc1, 0x97, 0x3f, 0x7d, 0x78, 0x0a,
                0xb3, 0x95, 0x18, 0x62, 0x68, 0x03, 0xd7, 0x82,
            };
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[64];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            privkey[8] = 189; /* just so there's some bits set */
            Sc_clamp.sc_clamp(privkey);

            /* Signature vector test */
            Keygen.curve25519_keygen(pubkey, privkey);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Curve_sigs.curve25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

            CollectionAssert.AreEqual(signature_correct, signature, "Curvesig sign");

            Assert.AreEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "Curvesig verify #1");

            signature[0] ^= 1;

            Assert.AreNotEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "Curvesig verify #2");
        }

        [TestMethod]
        public void xeddsa_fast_test()
        {
            byte[] signature_correct = new byte[]
            {
                0x11, 0xc7, 0xf3, 0xe6, 0xc4, 0xdf, 0x9e, 0x8a,
                0x51, 0x50, 0xe1, 0xdb, 0x3b, 0x30, 0xf9, 0x2d,
                0xe3, 0xa3, 0xb3, 0xaa, 0x43, 0x86, 0x56, 0x54,
                0x5f, 0xa7, 0x39, 0x0f, 0x4b, 0xcc, 0x7b, 0xb2,
                0x6c, 0x43, 0x1d, 0x9e, 0x90, 0x64, 0x3e, 0x4f,
                0x0e, 0xaa, 0x0e, 0x9c, 0x55, 0x77, 0x66, 0xfa,
                0x69, 0xad, 0xa5, 0x76, 0xd6, 0x3d, 0xca, 0xf2,
                0xac, 0x32, 0x6c, 0x11, 0xd0, 0xb9, 0x77, 0x02,
            };
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[64];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            privkey[8] = 189; /* just so there's some bits set */
            Sc_clamp.sc_clamp(privkey);

            /* Signature vector test */
            Keygen.curve25519_keygen(pubkey, privkey);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            xeddsa.xed25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);
            CollectionAssert.AreEqual(signature_correct, signature, "XEdDSA sign");
            Assert.AreEqual(0, xeddsa.xed25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "XEdDSA verify #1");
            signature[0] ^= 1;
            Assert.AreNotEqual(0, xeddsa.xed25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "XEdDSA verify #2");
            Memset(pubkey, 0xff);
            Assert.AreNotEqual(0, xeddsa.xed25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "XEdDSA verify #3");
        }

        [TestMethod]
        public void vxeddsa_fast_test()
        {
            byte[] signature_correct = new byte[]
            {
                0x23, 0xc6, 0xe5, 0x93, 0x3f, 0xcd, 0x56, 0x47,
                0x7a, 0x86, 0xc9, 0x9b, 0x76, 0x2c, 0xb5, 0x24,
                0xc3, 0xd6, 0x05, 0x55, 0x38, 0x83, 0x4d, 0x4f,
                0x8d, 0xb8, 0xf0, 0x31, 0x07, 0xec, 0xeb, 0xa0,
                0xa0, 0x01, 0x50, 0xb8, 0x4c, 0xbb, 0x8c, 0xcd,
                0x23, 0xdc, 0x65, 0xfd, 0x0e, 0x81, 0xb2, 0x86,
                0x06, 0xa5, 0x6b, 0x0c, 0x4f, 0x53, 0x6d, 0xc8,
                0x8b, 0x8d, 0xc9, 0x04, 0x6e, 0x4a, 0xeb, 0x08,
                0xce, 0x08, 0x71, 0xfc, 0xc7, 0x00, 0x09, 0xa4,
                0xd6, 0xc0, 0xfd, 0x2d, 0x1a, 0xe5, 0xb6, 0xc0,
                0x7c, 0xc7, 0x22, 0x3b, 0x69, 0x59, 0xa8, 0x26,
                0x2b, 0x57, 0x78, 0xd5, 0x46, 0x0e, 0x0f, 0x05,
            };
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];
            byte[] vrf_out = new byte[32];
            byte[] vrf_outprev = new byte[32];

            privkey[8] = 189; /* just so there's some bits set */
            Sc_clamp.sc_clamp(privkey);

            /* Signature vector test */
            Keygen.curve25519_keygen(pubkey, privkey);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();

            vxeddsa.vxed25510_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);
            CollectionAssert.AreEqual(signature_correct, signature, "VXEdDSA sign");
            Assert.AreEqual(0, vxeddsa.vxed25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN), "VXEdDSA verify #1");
            Array.Copy(vrf_out, 0, vrf_outprev, 0, 32);
            signature[0] ^= 1;
            Assert.AreNotEqual(0, vxeddsa.vxed25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN), "VXEdDSA verify #2");

            Memset(pubkey, 0xff);
            Assert.AreNotEqual(0, vxeddsa.vxed25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN), "VXEdDSA verify #3");
            Keygen.curve25519_keygen(pubkey, privkey);

            /* Test U */
            byte[] sigprev = new byte[96];
            Array.Copy(signature, 0, sigprev, 0, 96);
            sigprev[0] ^= 1; /* undo prev disturbance */

            random[0] ^= 1;
            vxeddsa.vxed25510_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);
            Assert.AreEqual(0, vxeddsa.vxed25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN), "VXEdDSA verify #3");

            byte[] vrf0 = new byte[32];
            Array.Copy(vrf_outprev, 0, vrf0, 0, 32);
            byte[] vrfprev0 = new byte[32];
            Array.Copy(vrf_out, 0, vrfprev0, 0, 32);
            CollectionAssert.AreEqual(vrfprev0, vrf0, "VXEdDSA VRF value unchanged");

            byte[] sig32 = new byte[64];
            Array.Copy(signature, 32, sig32, 0, 64);
            byte[] sigprev32 = new byte[64];
            Array.Copy(sigprev, 32, sigprev32, 0, 64);
            CollectionAssert.AreNotEqual(sigprev32, sig32, "VXEdDSA (h, s) changed");
        }

        [TestMethod]
        [TestCategory("Long")]
        public void curvesigs_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0xfc, 0xba, 0x55, 0xc4, 0x85, 0x4a, 0x42, 0x25,
                0x19, 0xab, 0x08, 0x8d, 0xfe, 0xb5, 0x13, 0xb6,
                0x0d, 0x24, 0xbb, 0x16, 0x27, 0x55, 0x71, 0x48,
                0xdd, 0x20, 0xb1, 0xcd, 0x2a, 0xd6, 0x7e, 0x35,
                0xef, 0x33, 0x4c, 0x7b, 0x6d, 0x94, 0x6f, 0x52,
                0xec, 0x43, 0xd7, 0xe6, 0x35, 0x24, 0xcd, 0x5b,
                0x5d, 0xdc, 0xb2, 0x32, 0xc6, 0x22, 0x53, 0xf3,
                0x38, 0x02, 0xf8, 0x28, 0x28, 0xc5, 0x65, 0x05,
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[64];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];
            /* Signature random test */
            Debug.WriteLine("Pseudorandom curvesigs...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 64);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                Curve_sigs.curve25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"Curvesig verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 64] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"Curvesig verify failure #2 {count}");

                if (count == 10000)
                {
                    CollectionAssert.AreEqual(signature_10k_correct, signature, $"Curvesig signature 10K doesn't match {count}");
                }
                if (count == 100000)
                {
                    //utility.print_bytes("100K curvesigs", signature, 64);
                }
                if (count == 1000000)
                {
                    //utility.print_bytes("1M curvesigs", signature, 64);
                }
                if (count == 10000000)
                {
                    //utility.print_bytes("10M curvesigs", signature, 64);
                }
            }
        }

        [TestMethod]
        [TestCategory("Long")]
        public void xeddsa_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0x15, 0x29, 0x03, 0x38, 0x66, 0x16, 0xcd, 0x26,
                0xbb, 0x3e, 0xec, 0xe2, 0x9f, 0x72, 0xa2, 0x5c,
                0x7d, 0x05, 0xc9, 0xcb, 0x84, 0x3f, 0x92, 0x96,
                0xb3, 0xfb, 0xb9, 0xdd, 0xd6, 0xed, 0x99, 0x04,
                0xc1, 0xa8, 0x02, 0x16, 0xcf, 0x49, 0x3f, 0xf1,
                0xbe, 0x69, 0xf9, 0xf1, 0xcc, 0x16, 0xd7, 0xdc,
                0x6e, 0xd3, 0x78, 0xaa, 0x04, 0xeb, 0x71, 0x51,
                0x9d, 0xe8, 0x7a, 0x5b, 0xd8, 0x49, 0x7b, 0x05,
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            for (int i = 0; i < 64; i++)
            {
                signature[i] = 1;
            }

            /* Signature random test */
            Debug.WriteLine("Pseudorandom XEdDSA...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 64);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                xeddsa.xed25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, xeddsa.xed25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XEdDSA verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 64] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, xeddsa.xed25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XEdDSA verify failure #2 {count}");

                if (count == 10000)
                {
                    byte[] sig0 = new byte[64];
                    Array.Copy(signature, 0, sig0, 0, 64);
                    CollectionAssert.AreEqual(signature_10k_correct, sig0, $"XEdDSA signature 10K doesn't match {count}");
                }
            }
        }

        [TestMethod]
        [TestCategory("Long")]
        public void xeddsa_to_curvesigs_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0x33, 0x50, 0xa8, 0x68, 0xcd, 0x9e, 0x74, 0x99,
                0xa3, 0x5c, 0x33, 0x75, 0x2b, 0x22, 0x03, 0xf8,
                0xb5, 0x0f, 0xea, 0x8c, 0x33, 0x1c, 0x68, 0x8b,
                0xbb, 0xf3, 0x31, 0xcf, 0x7c, 0x42, 0x37, 0x35,
                0xa0, 0x0e, 0x15, 0xb8, 0x5d, 0x2b, 0xe1, 0xa2,
                0x03, 0x77, 0x94, 0x3d, 0x13, 0x5c, 0xd4, 0x9b,
                0x6a, 0x31, 0xf4, 0xdc, 0xfe, 0x24, 0xad, 0x54,
                0xeb, 0xd2, 0x98, 0x47, 0xf1, 0xcc, 0xbf, 0x0d
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            for (int i = 0; i < 64; i++)
            {
                signature[i] = 2;
            }

            /* Signature random test */
            Debug.WriteLine("Pseudorandom XEdDSA/Curvesigs...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 64);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                xeddsa.xed25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XEdDSA/Curvesigs verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 64] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XEdDSA/Curvesigs verify failure #2 {count}");

                if (count == 10000)
                {
                    byte[] sig0 = new byte[64];
                    Array.Copy(signature, 0, sig0, 0, 64);
                    CollectionAssert.AreEqual(signature_10k_correct, sig0, $"XEdDSA/Curvesigs signature 10K doesn't match {count}");
                }
                if (count == 100000)
                {
                    //utility.print_bytes("100K XEdDSA/C", signature, 64);
                }
                if (count == 1000000)
                {
                    //utility.print_bytes("1M XEdDSA/C", signature, 64);
                }
                if (count == 10000000)
                {
                    //utility.print_bytes("10M XEdDSA/C", signature, 64);
                }
            }
        }

        [TestMethod]
        [TestCategory("Very Long")]
        public void vxeddsa_slow_test()
        {
            int iterations = 10000000;
            //int iterations = 100000;
            byte[] signature_10k_correct = new byte[]
            {
                0xa1, 0x96, 0x96, 0xe5, 0x87, 0x3f, 0x6e, 0x5c,
                0x2e, 0xd3, 0x73, 0xab, 0x04, 0x0c, 0x1f, 0x26,
                0x3c, 0xca, 0x52, 0xc4, 0x7e, 0x49, 0xaa, 0xce,
                0xb5, 0xd6, 0xa2, 0x29, 0x46, 0x3f, 0x1b, 0x54,
                0x45, 0x94, 0x9b, 0x6c, 0x27, 0xf9, 0x2a, 0xed,
                0x17, 0xa4, 0x72, 0xbf, 0x35, 0x37, 0xc1, 0x90,
                0xac, 0xb3, 0xfd, 0x2d, 0xf1, 0x01, 0x05, 0xbe,
                0x56, 0x5c, 0xaf, 0x63, 0x65, 0xad, 0x38, 0x04,
                0x70, 0x53, 0xdf, 0x2b, 0xc1, 0x45, 0xc8, 0xee,
                0x02, 0x0d, 0x2b, 0x22, 0x23, 0x7a, 0xbf, 0xfa,
                0x43, 0x31, 0xb3, 0xac, 0x26, 0xd9, 0x76, 0xfc,
                0xfe, 0x30, 0xa1, 0x7c, 0xce, 0x10, 0x67, 0x0e,
            };

            /*
            byte[] signature_100k_correct = new byte[]
            {
                0xc9, 0x11, 0x2b, 0x55, 0xfa, 0xc4, 0xb2, 0xfe,
                0x00, 0x7d, 0xf6, 0x45, 0xcb, 0xd2, 0x73, 0xc9,
                0x43, 0xba, 0x20, 0xf6, 0x9c, 0x18, 0x84, 0xef,
                0x6c, 0x65, 0x7a, 0xdb, 0x49, 0xfc, 0x1e, 0xbe,
                0x31, 0xb3, 0xe6, 0xa4, 0x68, 0x2f, 0xd0, 0x30,
                0x81, 0xfc, 0x0d, 0xcd, 0x2d, 0x00, 0xab, 0xae,
                0x9f, 0x08, 0xf0, 0x99, 0xff, 0x9f, 0xdc, 0x2d,
                0x68, 0xd6, 0xe7, 0xe8, 0x44, 0x2a, 0x5b, 0x0e,
                0x48, 0x67, 0xe2, 0x41, 0x4a, 0xd9, 0x0c, 0x2a,
                0x2b, 0x4e, 0x66, 0x09, 0x87, 0xa0, 0x6b, 0x3b,
                0xd1, 0xd9, 0xa3, 0xe3, 0xa5, 0x69, 0xed, 0xc1,
                0x42, 0x03, 0x93, 0x0d, 0xbc, 0x7e, 0xe9, 0x08,
            };

            byte[] signature_1m_correct = new byte[]
            {
                0xf8, 0xb1, 0x20, 0xf2, 0x1e, 0x5c, 0xbf, 0x5f,
                0xea, 0x07, 0xcb, 0xb5, 0x77, 0xb8, 0x03, 0xbc,
                0xcb, 0x6d, 0xf1, 0xc1, 0xa5, 0x03, 0x05, 0x7b,
                0x01, 0x63, 0x9b, 0xf9, 0xed, 0x3e, 0x57, 0x47,
                0xd2, 0x5b, 0xf4, 0x7e, 0x7c, 0x45, 0xce, 0xfc,
                0x06, 0xb3, 0xf4, 0x05, 0x81, 0x9f, 0x53, 0xb0,
                0x18, 0xe3, 0xfa, 0xcb, 0xb2, 0x52, 0x3e, 0x57,
                0xcb, 0x34, 0xcc, 0x81, 0x60, 0xb9, 0x0b, 0x04,
                0x07, 0x79, 0xc0, 0x53, 0xad, 0xc4, 0x4b, 0xd0,
                0xb5, 0x7d, 0x95, 0x4e, 0xbe, 0xa5, 0x75, 0x0c,
                0xd4, 0xbf, 0xa7, 0xc0, 0xcf, 0xba, 0xe7, 0x7c,
                0xe2, 0x90, 0xef, 0x61, 0xa9, 0x29, 0x66, 0x0d,
            };

            byte[] signature_10m_correct = new byte[]
            {
                0xf5, 0xa4, 0xbc, 0xec, 0xc3, 0x3d, 0xd0, 0x43,
                0xd2, 0x81, 0x27, 0x9e, 0xf0, 0x4c, 0xbe, 0xf3,
                0x77, 0x01, 0x56, 0x41, 0x0e, 0xff, 0x0c, 0xb9,
                0x66, 0xec, 0x4d, 0xe0, 0xb7, 0x25, 0x63, 0x6b,
                0x5c, 0x08, 0x39, 0x80, 0x4e, 0x37, 0x1b, 0x2c,
                0x46, 0x6f, 0x86, 0x99, 0x1c, 0x4e, 0x31, 0x60,
                0xdb, 0x4c, 0xfe, 0xc5, 0xa2, 0x4d, 0x71, 0x2b,
                0xd6, 0xd0, 0xc3, 0x98, 0x88, 0xdb, 0x0e, 0x0c,
                0x68, 0x4a, 0xd3, 0xc7, 0x56, 0xac, 0x8d, 0x95,
                0x7b, 0xbd, 0x99, 0x50, 0xe8, 0xd3, 0xea, 0xf3,
                0x7b, 0x26, 0xf2, 0xa2, 0x2b, 0x02, 0x58, 0xca,
                0xbd, 0x2c, 0x2b, 0xf7, 0x77, 0x58, 0xfe, 0x09,
            };
            */

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];
            byte[] vrf_out = new byte[32];

            for (int i = 0; i < 96; i++)
            {
                signature[i] = 3;
            }

            Debug.WriteLine("Pseudorandom VXEdDSA...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 96);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                vxeddsa.vxed25510_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, vxeddsa.vxed25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN), $"VXEdDSA verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 96] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, vxeddsa.vxed25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN), $"VXEdDSA verify failure #2 {count}");

                //if (count == 10000)
                //    print_bytes("10K VXEdDSA", signature, 96);
                //if (count == 100000)
                //    print_bytes("100K VXEdDSA", signature, 96);
                //if (count == 1000000)
                //    print_bytes("1M VXEdDSA", signature, 96);
                //if (count == 10000000)
                //    print_bytes("10M VXEdDSA", signature, 96);
                //if (count == 100000000)
                //    print_bytes("100M VXEdDSA", signature, 96);

                if (count == 10000)
                {
                    CollectionAssert.AreEqual(signature_10k_correct, signature, $"VXEdDSA 10K doesn't match {count}");
                }
                /*
                if (count == 100000)
                {
                    CollectionAssert.AreEqual(signature_100k_correct, signature, $"VXEdDSA 100K doesn't match {count}");
                }
                if (count == 1000000)
                {
                    CollectionAssert.AreEqual(signature_1m_correct, signature, $"VXEdDSA 1m doesn't match {count}");
                }
                if (count == 10000000)
                {
                    CollectionAssert.AreEqual(signature_10m_correct, signature, $"VXEdDSA 10m doesn't match {count}");
                }
                if (count == 100000000) {
                    if (memcmp(signature, signature_100m_correct, 96) != 0)
                        ERROR("VXEDDSA 100m doesn't match %d\n", count);
                }
                */
            }
        }
    }
}
