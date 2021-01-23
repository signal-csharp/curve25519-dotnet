﻿using System;
using System.Text;
using curve25519_dotnet.csharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using org.whispersystems.curve25519;
using org.whispersystems.curve25519.csharp;

namespace curve25519Tests
{
    [TestClass]
    public class InternalFastTests
    {
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
            Arrays.Fill(pubkey, 0xff);
            Assert.AreNotEqual(0, xeddsa.xed25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "XEdDSA verify #3");
        }

        [TestMethod]
        public void generalized_xeddsa_fast_test()
        {
            Span<byte> signature1 = new Span<byte>(new byte[64]);
            Span<byte> signature2 = new Span<byte>(new byte[64]);
            Span<byte> privkey = new Span<byte>(new byte[32]);
            Span<byte> pubkey = new Span<byte>(new byte[32]);
            Span<byte> msg1 = new Span<byte>(new byte[1000]);
            Span<byte> msg2 = new Span<byte>(new byte[1000]);
            Span<byte> random = new Span<byte>(new byte[64]);

            Arrays.Fill(privkey, 0xF0);
            Arrays.Fill(pubkey, 2);
            Arrays.Fill(msg1, 0x10);
            Arrays.Fill(msg2, 0x20);
            Arrays.Fill(random, 0xBC);

            Sc_clamp.sc_clamp(privkey);
            Keygen.curve25519_keygen(pubkey, privkey);

            msg2[0] = 1;

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Assert.AreEqual(0, Gen_x.generalized_xeddsa_25519_sign(sha512provider, signature1, privkey, msg1, 100, random, null, 0), "generalized xeddsa sign #1");
            Assert.AreEqual(0, Gen_x.generalized_xeddsa_25519_sign(sha512provider, signature2, privkey, msg2, 100, random, null, 0), "generalized xeddsa sign #2");

            Assert.AreEqual(0, xeddsa.xed25519_verify(sha512provider, signature1.ToArray(), pubkey.ToArray(), msg1.ToArray(), 100), "generalized (old) xeddsa verify #1");
            Assert.AreEqual(0, xeddsa.xed25519_verify(sha512provider, signature2.ToArray(), pubkey.ToArray(), msg2.ToArray(), 100), "generalized (old) xeddsa verify #2");
            Assert.AreNotEqual(0, xeddsa.xed25519_verify(sha512provider, signature1.ToArray(), pubkey.ToArray(), msg2.ToArray(), 100), "generalized (old) xeddsa verify #3");
            Assert.AreNotEqual(0, xeddsa.xed25519_verify(sha512provider, signature2.ToArray(), pubkey.ToArray(), msg1.ToArray(), 100), "generalized (old) xeddsa verify #4");

            Assert.AreEqual(0, Gen_x.generalized_xeddsa_25519_verify(sha512provider, signature1, pubkey, msg1, 100, null, 0), "generalized xeddsa verify #1");
            Assert.AreEqual(0, Gen_x.generalized_xeddsa_25519_verify(sha512provider, signature2, pubkey, msg2, 100, null, 0), "generalized xeddsa verify #2");
            Assert.AreNotEqual(0, Gen_x.generalized_xeddsa_25519_verify(sha512provider, signature1, pubkey, msg2, 100, null, 0), "generalized xeddsa verify #3");
            Assert.AreNotEqual(0, Gen_x.generalized_xeddsa_25519_verify(sha512provider, signature2, pubkey, msg1, 100, null, 0), "generalized xeddsa verify #4");
        }

        [TestMethod]
        public void generalized_xveddsa_fast_test()
        {
            Span<byte> signature1 = new Span<byte>(new byte[96]);
            Span<byte> signature2 = new Span<byte>(new byte[96]);
            Span<byte> privkey = new Span<byte>(new byte[32]);
            Span<byte> pubkey = new Span<byte>(new byte[32]);
            Span<byte> msg1 = new Span<byte>(new byte[1000]);
            Span<byte> msg2 = new Span<byte>(new byte[1000]);
            Span<byte> random = new Span<byte>(new byte[64]);
            Span<byte> vrf = new Span<byte>(new byte[32]);

            Arrays.Fill(privkey, 1);
            Arrays.Fill(pubkey, 2);
            Arrays.Fill(msg1, 0x11);
            Arrays.Fill(msg2, 0x22);
            Arrays.Fill(random, 0xAB);

            Sc_clamp.sc_clamp(privkey);
            Keygen.curve25519_keygen(pubkey, privkey);

            msg2[0] ^= 1;

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_sign(sha512provider, signature1, privkey, msg1, 100, random, null, 0), "generalized xveddsa sign #1");
            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_sign(sha512provider, signature2, privkey, msg2, 100, random, Encoding.UTF8.GetBytes("abc"), 3), "generalized xveddsa sign #2");

            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf, signature1, pubkey, msg1, 100, null, 0), "generalized xveddsa verify #1");
            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf, signature2, pubkey, msg2, 100, Encoding.UTF8.GetBytes("abc"), 3), "generalized xveddsa verify #2");
            Assert.AreNotEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf, signature1, pubkey, msg2, 100, null, 0), "generalized xveddsa verify #3");
            Assert.AreNotEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf, signature2, pubkey, msg1, 100, Encoding.UTF8.GetBytes("abc"), 3), "generalized xveddsa verify #4");

            Span<byte> signature3 = new Span<byte>(new byte[96]);
            Span<byte> vrf3 = new Span<byte>(new byte[96]);
            random[0] ^= 1;
            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_sign(sha512provider, signature3, privkey, msg1, 100, random, null, 0), "generalized xveddsa sign #3");
            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf, signature1, pubkey, msg1, 100, null, 0), "generalized xveddsa verify #5");
            Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf3, signature3, pubkey, msg1, 100, null, 0), "generalized xveddsa verify #6");
            Assert.IsTrue(vrf.SequenceEqual(vrf3.Slice(0, 32)), "generalized xveddsa VRFs equal");
            Assert.IsTrue(signature1.Slice(0, 32).SequenceEqual(signature3.Slice(0, 32)), "generalized xveddsa Kv equal");
            Assert.IsFalse(signature1.Slice(32, 32).SequenceEqual(signature3.Slice(32, 32)), "generalized xveddsa h not equal");
            Assert.IsFalse(signature1.Slice(64, 32).SequenceEqual(signature3.Slice(64, 32)), "generalized xveddsa s not equal");
        }
    }
}
