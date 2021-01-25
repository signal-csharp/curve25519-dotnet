using System;

namespace org.whispersystems.curve25519.csharp
{
    public class Gen_eddsa
    {
        /* B: base point 
         * R: commitment (point), 
           r: private nonce (scalar)
           K: encoded public key
           k: private key (scalar)
           Z: 32-bytes random
           M: buffer containing message, message starts at M_start, continues for M_len
           r = hash(B || labelset || Z || pad1 || k || pad2 || labelset || K || extra || M) (mod q)
        */
        public static int generalized_commit(ISha512 sha512provider, byte[] R_bytes, byte[] r_scalar,
            byte[] labelset, uint labelset_len,
            byte[] extra, uint extra_len,
            byte[] K_bytes, byte[] k_scalar,
            byte[] Z,
            byte[] M_buf, uint M_start, uint M_len)
        {
            Ge_p3 R_point = new Ge_p3();
            byte[] hash = new byte[Gen_constants.HASHLEN];
            int bufstart = 0;
            int? bufptr = 0;
            int bufend = 0;
            uint prefix_len = 0;

            if (Gen_labelset.labelset_validate(labelset, labelset_len) != 0)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }
            if (R_bytes == null || r_scalar == null ||
                K_bytes == null || k_scalar == null ||
                Z == null || M_buf == null)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }
            if (labelset == null && labelset_len != 0)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }
            if (extra == null && extra_len != 0)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }
            //if (Gen_constants.HASHLEN != 64)
            //{
            //    Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
            //    Zeroize.zeroize(M_buf, (int)M_start);
            //    return -1;
            //}

            prefix_len = 0;
            prefix_len += Gen_constants.POINTLEN + labelset_len + Gen_constants.RANDLEN;
            prefix_len += (Gen_constants.BLOCKLEN - (prefix_len % Gen_constants.BLOCKLEN)) % Gen_constants.BLOCKLEN;
            prefix_len += Gen_constants.SCALARLEN;
            prefix_len += (Gen_constants.BLOCKLEN - (prefix_len % Gen_constants.BLOCKLEN)) % Gen_constants.BLOCKLEN;
            prefix_len += labelset_len + Gen_constants.POINTLEN + extra_len;
            if (prefix_len > M_start)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }

            bufstart = (int)(M_start - prefix_len);
            bufptr = bufstart;
            bufend = (int)M_start;
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, Gen_labelset.B_bytes, Gen_constants.POINTLEN);
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, labelset, labelset_len);
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, Z, Gen_constants.RANDLEN);
            bufptr += Gen_labelset.buffer_pad(M_buf, bufstart, bufptr, bufend);
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, k_scalar, Gen_constants.SCALARLEN);
            bufptr += Gen_labelset.buffer_pad(M_buf, bufstart, bufptr, bufend);
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, labelset, labelset_len);
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, K_bytes, Gen_constants.POINTLEN);
            bufptr += Gen_labelset.buffer_add(M_buf, bufptr, extra, extra_len);
            if (bufptr != bufend || bufptr != M_start || bufptr - bufstart != prefix_len)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }

            byte[] hashIn = new byte[prefix_len + M_len];
            Array.Copy(M_buf, (int)(M_start - prefix_len), hashIn, 0, (int)(prefix_len + M_len));
            sha512provider.calculateDigest(hash, hashIn, prefix_len + M_len);
            Sc_reduce.sc_reduce(hash);
            Ge_scalarmult_base.ge_scalarmult_base(R_point, hash);
            Ge_p3_tobytes.ge_p3_tobytes(R_bytes, R_point);
            Array.Copy(hash, 0, r_scalar, 0, (int)Gen_constants.SCALARLEN);

            Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
            Zeroize.zeroize(M_buf, bufstart, (int)prefix_len);
            return 0;
        }

        /* if is_labelset_empty(labelset):
               return hash(R || K || M) (mod q)
           else:
               return hash(B || labelset || R || labelset || K || extra || M) (mod q)
        */
        public static int generalized_challenge(ISha512 sha512provider, byte[] h_scalar,
            byte[] labelset, uint labelset_len,
            byte[] extra, uint extra_len,
            byte[] R_bytes,
            byte[] K_bytes,
            byte[] M_buf, uint M_start, uint M_len)
        {
            byte[] hash = new byte[Gen_constants.HASHLEN];
            int bufstart = 0;
            int? bufptr = null;
            int bufend = 0;
            uint prefix_len = 0;

            if (Gen_labelset.labelset_validate(labelset, labelset_len) != 0)
                return -1;
            if (h_scalar == null || R_bytes == null || K_bytes == null || M_buf == null)
                return -1;
            if (labelset == null && labelset_len != 0)
                return -1;
            if (extra == null && extra_len != 0)
                return -1;
            //if (Gen_constants.HASHLEN != 64)
            //    return -1;

            if (Gen_labelset.labelset_is_empty(labelset, labelset_len))
            {
                if (2 * Gen_constants.POINTLEN > M_start)
                    return -1;
                Array.Copy(R_bytes, 0, M_buf, (int)M_start - (2 * (int)Gen_constants.POINTLEN), (int)Gen_constants.POINTLEN);
                Array.Copy(K_bytes, 0, M_buf, (int)M_start - (1 * (int)Gen_constants.POINTLEN), (int)Gen_constants.POINTLEN);
                prefix_len = 2 * Gen_constants.POINTLEN;
            }
            else
            {
                prefix_len = 3 * Gen_constants.POINTLEN + 2 * labelset_len + extra_len;
                if (prefix_len > M_start)
                    return -1;

                bufstart = (int)(M_start - prefix_len);
                bufptr = bufstart;
                bufend = (int)M_start;
                bufptr += Gen_labelset.buffer_add(M_buf, bufptr, Gen_labelset.B_bytes, Gen_constants.POINTLEN);
                bufptr += Gen_labelset.buffer_add(M_buf, bufptr, labelset, labelset_len);
                bufptr += Gen_labelset.buffer_add(M_buf, bufptr, R_bytes, Gen_constants.POINTLEN);
                bufptr += Gen_labelset.buffer_add(M_buf, bufptr, labelset, labelset_len);
                bufptr += Gen_labelset.buffer_add(M_buf, bufptr, K_bytes, Gen_constants.POINTLEN);
                bufptr += Gen_labelset.buffer_add(M_buf, bufptr, extra, extra_len);
                if (bufptr == null)
                    return -1;
                if (bufptr != bufend || bufptr != M_start || bufptr - bufstart != prefix_len)
                    return -1;
            }

            byte[] hashIn = new byte[prefix_len + M_len];
            Array.Copy(M_buf, (int)(M_start - prefix_len), hashIn, 0, (int)(prefix_len + M_len));
            sha512provider.calculateDigest(hash, hashIn, prefix_len + M_len);
            Sc_reduce.sc_reduce(hash);
            Array.Copy(hash, h_scalar, (int)Gen_constants.SCALARLEN);
            return 0;
        }

        /* return r + kh (mod q) */
        public static int generalized_prove(byte[] out_scalar,
            byte[] r_scalar, byte[] k_scalar, byte[] h_scalar)
        {
            Sc_muladd.sc_muladd(out_scalar, h_scalar, k_scalar, r_scalar);
            //zeroize_stack();
            return 0;
        }

        public static int generalized_solve_commitment(byte[] R_bytes_out, Ge_p3 K_point_out,
            Ge_p3 B_point, byte[] s_scalar,
            byte[] K_bytes, byte[] h_scalar)
        {
            Ge_p3 Kneg_point = new Ge_p3();
            Ge_p2 R_calc_point_p2 = new Ge_p2();

            Ge_p3 sB = new Ge_p3();
            Ge_p3 hK = new Ge_p3();
            Ge_cached hK_cached = new Ge_cached();
            Ge_p3 R_calc_point_p3 = new Ge_p3();
            Ge_p1p1 Rp1p1 = new Ge_p1p1();

            if (Ge_frombytes.ge_frombytes_negate_vartime(Kneg_point, K_bytes) != 0)
                return -1;

            if (B_point == null)
            {
                Ge_double_scalarmult.ge_double_scalarmult_vartime(R_calc_point_p2, h_scalar, Kneg_point, s_scalar);
                Ge_tobytes.ge_tobytes(R_bytes_out, R_calc_point_p2);
            }
            else
            {
                // s * Bv
                Ge_scalarmult.ge_scalarmult(sB, s_scalar, B_point);

                // h * -K
                Ge_scalarmult.ge_scalarmult(hK, h_scalar, Kneg_point);

                // R = sB - hK
                Ge_p3_to_cached.ge_p3_to_cached(hK_cached, hK);
                Ge_add.ge_add(Rp1p1, sB, hK_cached);
                Ge_p1p1_to_p3.ge_p1p1_to_p3(R_calc_point_p3, Rp1p1);
                Ge_p3_tobytes.ge_p3_tobytes(R_bytes_out, R_calc_point_p3);
            }

            if (K_point_out != null)
            {
                Ge_neg.ge_neg(K_point_out, Kneg_point);
            }

            return 0;
        }

        public static int generalized_eddsa_25519_sign(
            ISha512 sha512provider,
            byte[] signature_out,
            byte[] eddsa_25519_pubkey_bytes,
            byte[] eddsa_25519_privkey_scalar,
            byte[] msg,
            uint msg_len,
            byte[] random,
            byte[] customization_label,
            uint customization_label_len)
        {
            byte[] labelset = new byte[Gen_constants.LABELSETMAXLEN];
            uint labelset_len = 0;
            byte[] R_bytes = new byte[Gen_constants.POINTLEN];
            byte[] r_scalar = new byte[Gen_constants.SCALARLEN];
            byte[] h_scalar = new byte[Gen_constants.SCALARLEN];
            byte[] s_scalar = new byte[Gen_constants.SCALARLEN];
            byte[] M_buf = null;

            // memset(signature_out, 0, SIGNATURELEN);

            M_buf = new byte[msg_len + Gen_constants.MSTART];
            // we slice to msg_len because the msg buffer may be longer than msg_len
            Array.Copy(msg, 0, M_buf, (int)Gen_constants.MSTART, (int)msg_len);

            // TODO: In curve25519-java labelset_new defines customization_label_len as a const unsigned char but in
            // this method it's defined as a const unsigned long. Is this a bug in curve25519-java?
            if (Gen_labelset.labelset_new(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN, null, 0,
                customization_label, (byte)customization_label_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack();
                //free(M_buf);
                return -1;
            }

            if (generalized_commit(sha512provider, R_bytes, r_scalar, labelset, labelset_len, null, 0,
                eddsa_25519_pubkey_bytes, eddsa_25519_privkey_scalar,
                random, M_buf, Gen_constants.MSTART, msg_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack();
                //free(M_buf);
                return -1;
            }

            if (generalized_challenge(sha512provider, h_scalar, labelset, labelset_len, null, 0,
                R_bytes, eddsa_25519_pubkey_bytes, M_buf, Gen_constants.MSTART, msg_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack();
                //free(M_buf);
                return -1;
            }

            if (generalized_prove(s_scalar, r_scalar, eddsa_25519_privkey_scalar, h_scalar) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack();
                //free(M_buf);
                return -1;
            }

            Array.Copy(R_bytes, signature_out, (int)Gen_constants.POINTLEN);
            Array.Copy(s_scalar, 0, signature_out, (int)Gen_constants.POINTLEN, (int)Gen_constants.SCALARLEN);

            Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
            //zeroize_stack();
            //free(M_buf);
            return 0;
        }

        public static int generalized_eddsa_25519_verify(
            ISha512 sha512provider,
            byte[] signature,
            byte[] eddsa_25519_pubkey_bytes,
            byte[] msg,
            uint msg_len,
            byte[] customization_label,
            uint customization_label_len)
        {
            byte[] labelset = new byte[Gen_constants.LABELSETMAXLEN];
            uint labelset_len = 0;
            byte[] R_bytes = null;
            byte[] s_scalar = null;
            byte[] h_scalar = new byte[Gen_constants.SCALARLEN];
            byte[] M_buf = null;
            byte[] R_calc_bytes = new byte[Gen_constants.POINTLEN];

            M_buf = new byte[msg_len + Gen_constants.MSTART];
            // we slice to msg_len because the msg buffer may be longer than msg_len
            Array.Copy(msg, 0, M_buf, (int)Gen_constants.MSTART, (int)msg_len);

            if (Gen_labelset.labelset_new(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN, null, 0,
                customization_label, (byte)customization_label_len) != 0)
            {
                return -1;
            }

            R_bytes = signature;
            s_scalar = new byte[signature.Length - Gen_constants.POINTLEN];
            Array.Copy(R_bytes, (int)Gen_constants.POINTLEN, s_scalar, 0, signature.Length - (int)Gen_constants.POINTLEN);

            if (!Point_isreduced.point_isreduced(eddsa_25519_pubkey_bytes))
                return -1;
            if (!Point_isreduced.point_isreduced(R_bytes))
                return -1;
            if (!Sc_isreduced.sc_isreduced(s_scalar))
                return -1;

            if (generalized_challenge(sha512provider, h_scalar, labelset, labelset_len,
                null, 0, R_bytes, eddsa_25519_pubkey_bytes, M_buf, Gen_constants.MSTART, msg_len) != 0)
                return -1;

            if (generalized_solve_commitment(R_calc_bytes, null, null,
                s_scalar, eddsa_25519_pubkey_bytes, h_scalar) != 0)
                return -1;

            if (Crypto_verify_32.crypto_verify_32(R_bytes, R_calc_bytes) != 0)
                return -1;

            return 0;
        }
    }
}
