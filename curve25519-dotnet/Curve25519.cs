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


using curve25519;
using System;
using System.Collections.Generic;
using System.Reflection;
/**
* Copyright (C) 2015 Open Whisper Systems
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
namespace org.whispersystems.curve25519
{
    /// <summary>
    /// A Curve25519 interface for generating keys, calculating agreements, creating signatures,
    /// and verifying signatures.
    /// </summary>
    /// <remarks>@author Moxie Marlinspike</remarks>
    public class Curve25519
    {
        /// <summary>
        /// Pure C#, PCL-compatible implementation
        /// </summary>
        public const string CSHARP   = "csharp";
        /// <summary>
        /// Pure C#, PCL-compatible, "donna"-optimized implementation
        /// </summary>
        public const string BEST = "best";

        public static Curve25519 getInstance(string type)
        {
            return getInstance(type, new BouncyCastleDotNETSha512Provider(), new PCLSecureRandomProvider());
        }

        public static Curve25519 getInstance(string type, csharp.ISha512 sha, SecureRandomProvider random)
        {
            switch (type)
            {
                case BEST:
                default:
                    {
                        return new Curve25519(constructBestProvider(sha, random));
                    }
                case CSHARP:
                    {
                        return new Curve25519(constructCSharpProvider(sha, random));
                    }
            }
        }

        private readonly Curve25519Provider provider;

        private Curve25519(Curve25519Provider provider)
        {
            this.provider = provider;
        }

        /// <summary>
        /// <see cref="Curve25519"/> is backed by either a native (via JNI)
        /// or pure-Java provider.  By default it prefers the native provider, and falls back to the
        /// pure-Java provider if the native library fails to load.
        /// </summary>
        /// <returns>true if backed by a native provider, false otherwise.</returns>
        public bool isNative()
        {
            return provider.isNative();
        }

        public byte [] generatePrivateKey()
        {
            return provider.generatePrivateKey();
        }

        public byte[] generatePrivateKey(byte[] random)
        {
            return provider.generatePrivateKey(random);
        }

        public byte [] generatePublicKey(byte [] privateKey)
        {
            return provider.generatePublicKey(privateKey);
        }

        /// <summary>
        /// Generates a Curve25519 keypair.
        /// </summary>
        /// <returns>A randomly generated Curve25519 keypair.</returns>
        public Curve25519KeyPair generateKeyPair()
        {
            byte[] privateKey = provider.generatePrivateKey();
            byte[] publicKey = provider.generatePublicKey(privateKey);

            return new Curve25519KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Calculates an ECDH agreement.
        /// </summary>
        /// <param name="publicKey">The Curve25519 (typically remote party's) public key.</param>
        /// <param name="privateKey">The Curve25519 (typically yours) private key.</param>
        /// <returns>A 32-byte shared secret.</returns>
        public byte[] calculateAgreement(byte[] publicKey, byte[] privateKey)
        {
            if (publicKey == null || privateKey == null)
            {
                throw new ArgumentException("Keys must not be null!");
            }

            if (publicKey.Length != 32 || privateKey.Length != 32)
            {
                throw new ArgumentException("Keys must be 32 bytes!");
            }

            return provider.calculateAgreement(privateKey, publicKey);
        }

        /// <summary>
        /// Calculates a Curve25519 signature.
        /// </summary>
        /// <param name="privateKey">The private Curve25519 key to create the signature with.</param>
        /// <param name="message">The message to sign.</param>
        /// <returns>A 64-byte signature.</returns>
        public byte[] calculateSignature(byte[] privateKey, byte[] message)
        {
            if (privateKey == null || privateKey.Length != 32)
            {
                throw new ArgumentException("Invalid private key length!");
            }

            byte[] random = provider.getRandom(64);
            return calculateSignature(random, privateKey, message);
        }

        public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            return provider.calculateSignature(random, privateKey, message);
        }

        /// <summary>
        /// Verify a Curve25519 signature.
        /// </summary>
        /// <param name="publicKey">The Curve25519 public key the signature belongs to.</param>
        /// <param name="message">The message that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>true if valid, false if not.</returns>
        public bool verifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || publicKey.Length != 32)
            {
                throw new ArgumentException("Invalid public key!");
            }

            if (message == null || signature == null || signature.Length != 64)
            {
                return false;
            }

            return provider.verifySignature(publicKey, message, signature);
        }

        /// <summary>
        /// Calculates a Unique Curve25519 signature.
        /// </summary>
        /// <param name="privateKey">The private Curve25519 key to create the signature with.</param>
        /// <param name="message">The message to sign.</param>
        /// <returns>A 96-byte signature.</returns>
        public byte[] calculateVrfSignature(byte[] privateKey, byte[] message)
        {
            if (privateKey == null || privateKey.Length != 32)
            {
                throw new ArgumentException("Invalid private key!");
            }

            byte[] random = provider.getRandom(64);
            return provider.calculateVrfSignature(random, privateKey, message);
        }

        /// <summary>
        /// Verify a Unique Curve25519 signature.
        /// </summary>
        /// <param name="publicKey">The Curve25519 public key the unique signature belongs to.</param>
        /// <param name="message">The message that was signed.</param>
        /// <param name="signature">The unique signature to verify.</param>
        /// <returns>The vrf for this signature</returns>
        public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || publicKey.Length != 32)
            {
                throw new ArgumentException("Invalid public key!");
            }

            if (message == null || signature == null || signature.Length != 96)
            {
                throw new VrfSignatureVerificationFailedException("Invalid message or signature format");
            }

            return provider.verifyVrfSignature(publicKey, message, signature);
        }

        private static Curve25519Provider constructCSharpProvider(csharp.ISha512 sha, SecureRandomProvider random)
        {
            return constructClass(typeof(CSharpCurve25519Provider), new object[] { sha, random });
        }
        private static Curve25519Provider constructBestProvider(csharp.ISha512 sha, SecureRandomProvider random)
        {
            return constructClass(typeof(DonnaCSharpCurve25519Provider), new object[] { sha, random });
        }
        /* TODO: Implement as appropriate to grow the flexibility of the library...
        private static Curve25519Provider constructNativeProvider(SecureRandomProvider random)
        {
            return constructClass("NativeCurve25519Provider", random);
        }
        */
        private static Curve25519Provider constructClass(Type curve25519Impl, object[] ctorParams)
        {
            if(ctorParams == null)
            {
                ctorParams = new object[] { };
            }
            Curve25519Provider provider = null;
            TypeInfo curve25519TypeInfo = curve25519Impl.GetTypeInfo();

            #region Validation: Class must implement Curve25519Provider base class
            Type baseType = curve25519TypeInfo.BaseType;
            bool basedOnCurve25519Provider = false;
            while (baseType != typeof(System.Object))
            {
                if(baseType == typeof(Curve25519Provider))
                {
                    basedOnCurve25519Provider = true;
                    break;
                }
                baseType = baseType.GetTypeInfo().BaseType;
            }
            if(!basedOnCurve25519Provider)
                throw new ArgumentException("Class must be a subclass of " + typeof(Curve25519Provider).Name);
            #endregion

            IEnumerator<ConstructorInfo> ctorEnum = curve25519TypeInfo.DeclaredConstructors.GetEnumerator();
            while (ctorEnum.MoveNext())
            {
                ConstructorInfo currCtor = ctorEnum.Current;
                ParameterInfo [] paramsInfo = currCtor.GetParameters();
                if(paramsInfo.Length == ctorParams.Length)
                {
                    provider = (Curve25519Provider)currCtor.Invoke(ctorParams);
                    break;
                }
            }
            return provider;
        }
    }
}
