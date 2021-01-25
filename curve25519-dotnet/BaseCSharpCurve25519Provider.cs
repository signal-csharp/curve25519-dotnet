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
using org.whispersystems.curve25519.csharp;

namespace org.whispersystems.curve25519
{
    /// <summary>
    /// Curve255919 in pure C#, without "donna" performance optimizations.
    /// </summary>
    public abstract class BaseCSharpCurve25519Provider : Curve25519Provider
    {
        private ISha512 sha512provider;
        private SecureRandomProvider secureRandomProvider;

        public BaseCSharpCurve25519Provider()
        {
            sha512provider = null;
            secureRandomProvider = null;
        }

        protected BaseCSharpCurve25519Provider(ISha512 sha512provider,
                                             SecureRandomProvider secureRandomProvider)
        {
            this.sha512provider = sha512provider;
            this.secureRandomProvider = secureRandomProvider;
        }

        public override void setRandomProvider(SecureRandomProvider secureRandomProvider)
        {
            this.secureRandomProvider = secureRandomProvider;
        }

        public override void setSha512Provider(ISha512 sha512Provider)
        {
            this.sha512provider = sha512Provider;
        }

        public override byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic)
        {
            byte[] agreement = new byte[32];
            Scalarmult.crypto_scalarmult(agreement, ourPrivate, theirPublic);

            return agreement;
        }

        public override byte[] generatePublicKey(byte[] privateKey)
        {
            byte[] publicKey = new byte[32];
            Keygen.curve25519_keygen(publicKey, privateKey);

            return publicKey;
        }

        public override byte[] generatePrivateKey()
        {
            byte[] random = getRandom(Curve25519Provider.PRIVATE_KEY_LEN);
            return generatePrivateKey(random);
        }

        public override byte[] generatePrivateKey(byte[] random)
        {
            byte[] privateKey = new byte[32];

            Array.Copy(random, 0, privateKey, 0, 32);

            privateKey[0] &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;

            return privateKey;
        }

        public override byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            byte[] result = new byte[64];

            if (xeddsa.xed25519_sign(sha512provider, result, privateKey, message, message.Length, random) != 0)
            {
                throw new ArgumentException("Message exceeds max length!");
            }

            return result;
        }

        public override bool verifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return Curve_sigs.curve25519_verify(sha512provider, signature, publicKey, message, message.Length) == 0;
        }

        public override byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            byte[] signature = new byte[96];

            if (Gen_x.generalized_xveddsa_25519_sign(sha512provider, signature, privateKey, message, (uint)message.Length, random, null, 0) != 0)
            {
                throw new ArgumentException("Signature failed!");
            }

            return signature;
        }

        public override byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            byte[] vrf = new byte[32];
            int result = Gen_x.generalized_xveddsa_25519_verify(sha512provider, vrf, signature, publicKey, message, (uint)message.Length, null, 0);

            if (result == 0)
            {
                return vrf;
            }
            else
            {
                throw new VrfSignatureVerificationFailedException("Invalid signature");
            }
        }

        public override byte[] getRandom(int length)
        {
            byte[] result = new byte[length];
            secureRandomProvider.nextBytes(result);
            return result;
        }
    }
}
