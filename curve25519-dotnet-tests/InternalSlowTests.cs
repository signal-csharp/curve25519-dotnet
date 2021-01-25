﻿using System;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using org.whispersystems.curve25519;
using org.whispersystems.curve25519.csharp;

namespace curve25519Tests
{
    [TestClass]
    public class InternalSlowTests
    {
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
        [Ignore]
        public void generalized_xveddsa_slow_test()
        {
            // 100,000 iterations takes about 18 minutes to run on a Ryzen 5 1600
            int iterations = 100000;
            byte[] signature_10k_correct = {
                0x89, 0x21, 0xf5, 0x2f, 0x37, 0x72, 0x08, 0x55,
                0x18, 0x9d, 0x24, 0xed, 0x86, 0xb1, 0x7a, 0x02,
                0xbf, 0x29, 0x5e, 0xa7, 0x45, 0xdc, 0x80, 0x03,
                0x7f, 0x4f, 0xca, 0x79, 0xe0, 0x95, 0xd0, 0xa1,
                0xb5, 0x99, 0xbe, 0xbd, 0xef, 0xbe, 0xa4, 0xdc,
                0x0c, 0x07, 0x6a, 0xf7, 0x7f, 0xe1, 0x1c, 0xb8,
                0x18, 0x84, 0xb8, 0xb4, 0xcf, 0x38, 0x7d, 0x98,
                0x37, 0xd8, 0x40, 0x23, 0x42, 0x12, 0x70, 0x06,
                0xb0, 0xd1, 0x0c, 0xc0, 0x1c, 0xa6, 0x9a, 0x2f,
                0xb4, 0x02, 0xd6, 0x37, 0x22, 0xe9, 0xfb, 0x00,
                0x22, 0x02, 0x5a, 0xf4, 0x40, 0x43, 0xb8, 0xe9,
                0xf4, 0x13, 0x44, 0x16, 0x19, 0x8d, 0x7e, 0x02,
            };
            byte[] signature_100k_correct = {
                0xc4, 0x99, 0x64, 0x1f, 0x94, 0x95, 0xf4, 0x57,
                0xa0, 0xb9, 0x3d, 0xc3, 0xb5, 0x2e, 0x1e, 0xdd,
                0x92, 0xf2, 0x4c, 0xb2, 0x01, 0x36, 0x3d, 0xf2,
                0xea, 0x2c, 0xdc, 0x32, 0x21, 0x5f, 0xc5, 0xd2,
                0xff, 0x16, 0x41, 0x71, 0x3a, 0x77, 0x79, 0xeb,
                0x67, 0x20, 0xc4, 0xec, 0x39, 0xe1, 0x54, 0x2d,
                0x40, 0x10, 0xf9, 0xca, 0xc5, 0x21, 0x0a, 0x47,
                0x63, 0x99, 0x23, 0x04, 0x9d, 0x03, 0x1a, 0x06,
                0x00, 0xb9, 0x56, 0x7e, 0xef, 0xee, 0x0b, 0x40,
                0x59, 0xc1, 0x86, 0xd9, 0xa7, 0x87, 0x70, 0xec,
                0x05, 0x89, 0xbe, 0x71, 0x43, 0xd1, 0xf5, 0x61,
                0x5e, 0x00, 0x41, 0xde, 0x1f, 0x41, 0x2d, 0x0e,
            };

            /*
              unsigned char signature_1m_correct[96] = {
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
              unsigned char signature_10m_correct[96] = {
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

            Arrays.Fill(signature, 3);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Debug.WriteLine("Pseudorandom XVEdDSA...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                sha512provider.calculateDigest(b, signature, 96);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                Gen_x.generalized_xveddsa_25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random, null, 0);

                Assert.AreEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN, null, 0), $"XVEdDSA verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                    signature[count % 96] ^= 1;
                else
                    msg[count % MSG_LEN] ^= 1;

                Assert.AreNotEqual(0, Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf_out, signature, pubkey, msg, MSG_LEN, null, 0), $"XVEdDSA verify failure #2 {count}");

                //if (count == 10000)
                //    print_bytes("10K XVEdDSA", signature, 96);
                //if (count == 100000)
                //    print_bytes("100K XVEdDSA", signature, 96);
                //if (count == 1000000)
                //    print_bytes("1M XVEdDSA", signature, 96);
                //if (count == 10000000)
                //    print_bytes("10M XVEdDSA", signature, 96);
                //if (count == 100000000)
                //    print_bytes("100M XVEdDSA", signature, 96);

                if (count == 10000)
                {
                    CollectionAssert.AreEqual(signature_10k_correct, signature, $"XVEDDSA 10K doesn't match {count}");
                }

                if (count == 100000)
                {
                    CollectionAssert.AreEqual(signature_100k_correct, signature, $"XVEDDSA 100K doesn't match {count}");
                }
            }
        }
    }
}
