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
        public static int generalized_commit(ISha512 sha512provider, Span<byte> R_bytes, Span<byte> r_scalar,
            ReadOnlySpan<byte> labelset, uint labelset_len,
            ReadOnlySpan<byte> extra, uint extra_len,
            ReadOnlySpan<byte> K_bytes, ReadOnlySpan<byte> k_scalar,
            ReadOnlySpan<byte> Z,
            Span<byte> M_buf, uint M_start, uint M_len)
        {
            Ge_p3 R_point = new Ge_p3();
            byte[] hashArr = new byte[Gen_constants.HASHLEN];
            Span<byte> hash = new Span<byte>(hashArr);
            Span<byte> bufstart = null;
            Span<byte> bufptr = null;
            Span<byte> bufend = null;
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

            bufstart = M_buf.Slice((int)(M_start - prefix_len));
            bufptr = bufstart;
            bufend = bufstart; // bufend isn't actually used but it cannot be null
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, Gen_labelset.B_bytes, Gen_constants.POINTLEN);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, labelset, labelset_len);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, Z, Gen_constants.RANDLEN);
            bufptr = Gen_labelset.buffer_pad(bufstart, bufptr, bufend);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, k_scalar, Gen_constants.SCALARLEN);
            bufptr = Gen_labelset.buffer_pad(bufstart, bufptr, bufend);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, labelset, labelset_len);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, K_bytes, Gen_constants.POINTLEN);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, extra, extra_len);
            if (bufptr == null || bufptr.Length != M_buf.Slice((int)M_start).Length)
            {
                Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
                Zeroize.zeroize(M_buf, (int)M_start);
                return -1;
            }

            sha512provider.calculateDigest(hashArr, M_buf.Slice((int)(M_start - prefix_len)).ToArray(), prefix_len + M_len);
            Sc_reduce.sc_reduce(hash);
            Ge_scalarmult_base.ge_scalarmult_base(R_point, hash);
            Ge_p3_tobytes.ge_p3_tobytes(R_bytes, R_point);
            hash.Slice(0, (int)Gen_constants.SCALARLEN).CopyTo(r_scalar);

            Zeroize.zeroize(hash, (int)Gen_constants.HASHLEN);
            Zeroize.zeroize(bufstart, (int)prefix_len);
            return 0;
        }

        /* if is_labelset_empty(labelset):
               return hash(R || K || M) (mod q)
           else:
               return hash(B || labelset || R || labelset || K || extra || M) (mod q)
        */
        public static int generalized_challenge(ISha512 sha512provider, Span<byte> h_scalar,
            ReadOnlySpan<byte> labelset, uint labelset_len,
            ReadOnlySpan<byte> extra, uint extra_len,
            ReadOnlySpan<byte> R_bytes,
            ReadOnlySpan<byte> K_bytes,
            Span<byte> M_buf, uint M_start, uint M_len)
        {
            byte[] hashArr = new byte[Gen_constants.HASHLEN];
            Span<byte> hash = new Span<byte>(hashArr);
            Span<byte> bufstart = null;
            Span<byte> bufptr = null;
            Span<byte> bufend = null;
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
                R_bytes.Slice(0, (int)Gen_constants.POINTLEN).CopyTo(M_buf.Slice((int)M_start - (2 * (int)Gen_constants.POINTLEN)));
                K_bytes.Slice(0, (int)Gen_constants.POINTLEN).CopyTo(M_buf.Slice((int)M_start - (1 * (int)Gen_constants.POINTLEN)));
                prefix_len = 2 * Gen_constants.POINTLEN;
            }
            else
            {
                prefix_len = 3 * Gen_constants.POINTLEN + 2 * labelset_len + extra_len;
                if (prefix_len > M_start)
                    return -1;

                bufstart = M_buf.Slice((int)(M_start - prefix_len));
                bufptr = bufstart;
                bufend = new Span<byte>(new byte[0]); // bufend isn't actually used but it cannot be null
                bufptr = Gen_labelset.buffer_add(bufptr, bufend, Gen_labelset.B_bytes, Gen_constants.POINTLEN);
                bufptr = Gen_labelset.buffer_add(bufptr, bufend, labelset, labelset_len);
                bufptr = Gen_labelset.buffer_add(bufptr, bufend, R_bytes, Gen_constants.POINTLEN);
                bufptr = Gen_labelset.buffer_add(bufptr, bufend, labelset, labelset_len);
                bufptr = Gen_labelset.buffer_add(bufptr, bufend, K_bytes, Gen_constants.POINTLEN);
                bufptr = Gen_labelset.buffer_add(bufptr, bufend, extra, extra_len);

                if (bufptr == null || bufptr.Length != M_buf.Slice((int)M_start).Length)
                    return -1;
            }

            sha512provider.calculateDigest(hashArr, M_buf.Slice((int)(M_start - prefix_len)).ToArray(), prefix_len + M_len);
            Sc_reduce.sc_reduce(hash);
            hash.Slice(0, (int)Gen_constants.SCALARLEN).CopyTo(h_scalar);
            return 0;
        }

        /* return r + kh (mod q) */
        public static int generalized_prove(Span<byte> out_scalar,
            ReadOnlySpan<byte> r_scalar, ReadOnlySpan<byte> k_scalar, ReadOnlySpan<byte> h_scalar)
        {
            Sc_muladd.sc_muladd(out_scalar, h_scalar, k_scalar, r_scalar);
            //zeroize_stack();
            return 0;
        }

        public static int generalized_solve_commitment(Span<byte> R_bytes_out, Ge_p3 K_point_out,
            Ge_p3 B_point, ReadOnlySpan<byte> s_scalar,
            ReadOnlySpan<byte> K_bytes, ReadOnlySpan<byte> h_scalar)
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
            Span<byte> signature_out,
            ReadOnlySpan<byte> eddsa_25519_pubkey_bytes,
            ReadOnlySpan<byte> eddsa_25519_privkey_scalar,
            ReadOnlySpan<byte> msg,
            uint msg_len,
            ReadOnlySpan<byte> random,
            ReadOnlySpan<byte> customization_label,
            uint customization_label_len)
        {
            Span<byte> labelset = new Span<byte>(new byte[Gen_constants.LABELSETMAXLEN]);
            uint labelset_len = 0;
            Span<byte> R_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> r_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> h_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> s_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> M_buf = null;

            // memset(signature_out, 0, SIGNATURELEN);

            M_buf = new Span<byte>(new byte[msg_len + Gen_constants.MSTART]);
            // we slice to msg_len because the msg buffer may be longer than msg_len
            msg.Slice(0, (int)msg_len).CopyTo(M_buf.Slice((int)Gen_constants.MSTART));

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

            R_bytes.CopyTo(signature_out);
            s_scalar.CopyTo(signature_out.Slice((int)Gen_constants.POINTLEN));

            Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
            //zeroize_stack();
            //free(M_buf);
            return 0;
        }

        public static int generalized_eddsa_25519_verify(
            ISha512 sha512provider,
            ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> eddsa_25519_pubkey_bytes,
            ReadOnlySpan<byte> msg,
            uint msg_len,
            ReadOnlySpan<byte> customization_label,
            uint customization_label_len)
        {
            Span<byte> labelset = new Span<byte>(new byte[Gen_constants.LABELSETMAXLEN]);
            uint labelset_len = 0;
            ReadOnlySpan<byte> R_bytes = null;
            ReadOnlySpan<byte> s_scalar = null;
            Span<byte> h_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> M_buf = null;
            Span<byte> R_calc_bytes = new byte[Gen_constants.POINTLEN];

            M_buf = new Span<byte>(new byte[msg_len + Gen_constants.MSTART]);
            // we slice to msg_len because the msg buffer may be longer than msg_len
            msg.Slice(0, (int)msg_len).CopyTo(M_buf.Slice((int)Gen_constants.MSTART));

            if (Gen_labelset.labelset_new(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN, null, 0,
                customization_label, (byte)customization_label_len) != 0)
            {
                return -1;
            }

            R_bytes = signature;
            s_scalar = signature.Slice((int)Gen_constants.POINTLEN);

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
