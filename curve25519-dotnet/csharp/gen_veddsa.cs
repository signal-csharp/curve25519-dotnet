using System;
using System.Text;

namespace org.whispersystems.curve25519.csharp
{
    public class Gen_veddsa
    {
        public static int generalized_calculate_Bv(ISha512 sha512provider, Ge_p3 Bv_point,
            ReadOnlySpan<byte> labelset, uint labelset_len,
            ReadOnlySpan<byte> K_bytes,
            Span<byte> M_buf, uint M_start, uint M_len)
        {
            uint prefix_len = 0;

            if (Gen_labelset.labelset_validate(labelset, labelset_len) != 0)
                return -1;
            if (Bv_point == null || K_bytes == null || M_buf == null)
                return -1;

            prefix_len = 2 * Gen_constants.POINTLEN + labelset_len;
            if (prefix_len > M_start)
                return -1;

            Gen_labelset.B_bytes.AsSpan(0, (int)Gen_constants.POINTLEN).CopyTo(M_buf.Slice((int)(M_start - prefix_len)));
            labelset.Slice(0, (int)labelset_len).CopyTo(M_buf.Slice((int)(M_start - prefix_len + Gen_constants.POINTLEN)));
            K_bytes.Slice(0, (int)Gen_constants.POINTLEN).CopyTo(M_buf.Slice((int)(M_start - prefix_len + Gen_constants.POINTLEN + labelset_len)));
            Elligator.hash_to_point(sha512provider, Bv_point, M_buf.Slice((int)(M_start - prefix_len)), (int)(prefix_len + M_len));
            if (Ge_isneutral.ge_isneutral(Bv_point) != 0)
                return -1;
            return 0;
        }

        public static int generalized_calculate_vrf_output(ISha512 sha512provider, Span<byte> vrf_output,
            ReadOnlySpan<byte> labelset, uint labelset_len,
            Ge_p3 cKv_point)
        {
            byte[] buf = new byte[Gen_constants.BUFLEN];
            Span<byte> bufptr = buf;
            Span<byte> bufend = new Span<byte>(new byte[0]);
            Span<byte> cKv_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            byte[] hashArr = new byte[Gen_constants.HASHLEN];
            Span<byte> hash = new Span<byte>(hashArr);

            if (labelset_len + 2 * Gen_constants.POINTLEN > Gen_constants.BUFLEN)
                return -1;
            if (Gen_labelset.labelset_validate(labelset, labelset_len) != 0)
                return -1;
            if (vrf_output == null || cKv_point == null)
                return -1;

            Ge_p3_tobytes.ge_p3_tobytes(cKv_bytes, cKv_point);

            bufptr = Gen_labelset.buffer_add(bufptr, bufend, Gen_labelset.B_bytes, Gen_constants.POINTLEN);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, labelset, labelset_len);
            bufptr = Gen_labelset.buffer_add(bufptr, bufend, cKv_bytes, Gen_constants.POINTLEN);
            if (bufptr == null)
                return -1;
            //if (bufptr - buf > BUFLEN)
            //return -1;
            sha512provider.calculateDigest(hashArr, buf, Gen_constants.POINTLEN + labelset_len + Gen_constants.POINTLEN);
            hash.Slice(0, (int)Gen_constants.VRFOUTPUTLEN).CopyTo(vrf_output);
            return 0;
        }

        public static int generalized_veddsa_25519_sign(
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
            Ge_p3 Bv_point = new Ge_p3();
            Ge_p3 Kv_point = new Ge_p3();
            Ge_p3 Rv_point = new Ge_p3();
            Span<byte> Bv_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> Kv_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> Rv_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> R_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> r_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> h_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> s_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> extra = new Span<byte>(new byte[3 * Gen_constants.POINTLEN]);
            Span<byte> M_buf = null;
            string protocol_name = "VEdDSA_25519_SHA512_Elligator2";

            Arrays.Fill(signature_out, 0, Gen_constants.VRFSIGNATURELEN);

            M_buf = new Span<byte>(new byte[msg_len + Gen_constants.MSTART]);
            msg.Slice(0, (int)msg_len).CopyTo(M_buf.Slice((int)Gen_constants.MSTART));

            // labelset = new_labelset(protocol_name, customization_label)
            if (Gen_labelset.labelset_new(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN,
                Encoding.UTF8.GetBytes(protocol_name), (byte)protocol_name.Length, customization_label, (byte)customization_label_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack()
                //free(M_buf);
                return -1;
            }

            // labelset1 = add_label(labels, "1")
            // Bv = hash(hash(labelset1 || K) || M)
            // Kv = k * Bv
            Gen_labelset.labelset_add(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN, Encoding.UTF8.GetBytes("1"), 1);
            if (generalized_calculate_Bv(sha512provider, Bv_point, labelset, labelset_len,
                eddsa_25519_pubkey_bytes, M_buf, Gen_constants.MSTART, msg_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack()
                //free(M_buf);
                return -1;
            }

            Ge_scalarmult.ge_scalarmult(Kv_point, eddsa_25519_privkey_scalar, Bv_point);
            Ge_p3_tobytes.ge_p3_tobytes(Bv_bytes, Bv_point);
            Ge_p3_tobytes.ge_p3_tobytes(Kv_bytes, Kv_point);

            // labelset2 = add_label(labels, "2")
            // R, r = commit(labelset2, (Bv || Kv), (K,k), Z, M)
            labelset[(int)labelset_len - 1] = Encoding.UTF8.GetBytes("2")[0];
            Bv_bytes.CopyTo(extra);
            Kv_bytes.CopyTo(extra.Slice((int)Gen_constants.POINTLEN));
            if (Gen_eddsa.generalized_commit(sha512provider, R_bytes, r_scalar,
                labelset, labelset_len,
                extra, 2 * Gen_constants.POINTLEN,
                eddsa_25519_pubkey_bytes, eddsa_25519_privkey_scalar,
                random, M_buf, Gen_constants.MSTART, msg_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack()
                //free(M_buf);
                return -1;
            }

            // Rv = r * Bv
            Ge_scalarmult.ge_scalarmult(Rv_point, r_scalar, Bv_point);
            Ge_p3_tobytes.ge_p3_tobytes(Rv_bytes, Rv_point);

            // labelset3 = add_label(labels, "3")
            // h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)
            labelset[(int)labelset_len - 1] = Encoding.UTF8.GetBytes("3")[0];
            Rv_bytes.CopyTo(extra.Slice(2 * (int)Gen_constants.POINTLEN));
            if (Gen_eddsa.generalized_challenge(sha512provider, h_scalar,
                labelset, labelset_len,
                extra, 3 * Gen_constants.POINTLEN,
                R_bytes, eddsa_25519_pubkey_bytes,
                M_buf, Gen_constants.MSTART, msg_len) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack()
                //free(M_buf);
                return -1;
            }

            // s = prove(r, k, h)
            if (Gen_eddsa.generalized_prove(s_scalar, r_scalar, eddsa_25519_privkey_scalar, h_scalar) != 0)
            {
                Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
                //zeroize_stack()
                //free(M_buf);
                return -1;
            }

            // return (Kv || h || s)
            Kv_bytes.CopyTo(signature_out);
            h_scalar.CopyTo(signature_out.Slice((int)Gen_constants.POINTLEN));
            s_scalar.CopyTo(signature_out.Slice((int)(Gen_constants.POINTLEN + Gen_constants.SCALARLEN)));

            Zeroize.zeroize(r_scalar, (int)Gen_constants.SCALARLEN);
            //zeroize_stack()
            //free(M_buf);
            return 0;
        }

        public static int generalized_veddsa_25519_verify(
            ISha512 sha512provider,
            Span<byte> vrf_out,
            ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> eddsa_25519_pubkey_bytes,
            ReadOnlySpan<byte> msg,
            uint msg_len,
            ReadOnlySpan<byte> customization_label,
            uint customization_label_len)
        {
            Span<byte> labelset = new Span<byte>(new byte[Gen_constants.LABELSETMAXLEN]);
            uint labelset_len = 0;
            ReadOnlySpan<byte> Kv_bytes = null;
            ReadOnlySpan<byte> h_scalar = null;
            ReadOnlySpan<byte> s_scalar = null;
            Ge_p3 Bv_point = new Ge_p3();
            Ge_p3 K_point = new Ge_p3();
            Ge_p3 Kv_point = new Ge_p3();
            Ge_p3 cK_point = new Ge_p3();
            Ge_p3 cKv_point = new Ge_p3();
            Span<byte> Bv_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> R_calc_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> Rv_calc_bytes = new Span<byte>(new byte[Gen_constants.POINTLEN]);
            Span<byte> h_calc_scalar = new Span<byte>(new byte[Gen_constants.SCALARLEN]);
            Span<byte> extra = new Span<byte>(new byte[3 * Gen_constants.POINTLEN]);
            Span<byte> M_buf = null;
            string protocol_name = "VEdDSA_25519_SHA512_Elligator2";

            M_buf = new Span<byte>(new byte[msg_len + Gen_constants.MSTART]);
            msg.Slice(0, (int)msg_len).CopyTo(M_buf.Slice((int)Gen_constants.MSTART));

            Kv_bytes = signature;
            h_scalar = signature.Slice((int)Gen_constants.POINTLEN);
            s_scalar = signature.Slice((int)(Gen_constants.POINTLEN + Gen_constants.SCALARLEN));

            if (!Point_isreduced.point_isreduced(eddsa_25519_pubkey_bytes))
                return -1;
            if (!Point_isreduced.point_isreduced(Kv_bytes))
                return -1;
            if (!Sc_isreduced.sc_isreduced(h_scalar))
                return -1;
            if (!Sc_isreduced.sc_isreduced(s_scalar))
                return -1;

            // labelset = new_labelset(protocol_name, customization_label)
            if (Gen_labelset.labelset_new(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN,
                Encoding.UTF8.GetBytes(protocol_name), (byte)protocol_name.Length,
                customization_label, (byte)customization_label_len) != 0)
                return -1;

            // labelset1 = add_label(labels, "1")
            // Bv = hash(hash(labelset1 || K) || M)
            Gen_labelset.labelset_add(labelset, ref labelset_len, Gen_constants.LABELSETMAXLEN, Encoding.UTF8.GetBytes("1"), 1);
            if (generalized_calculate_Bv(sha512provider, Bv_point, labelset, labelset_len,
                eddsa_25519_pubkey_bytes, M_buf, Gen_constants.MSTART, msg_len) != 0)
                return -1;
            Ge_p3_tobytes.ge_p3_tobytes(Bv_bytes, Bv_point);

            // R = solve_commitment(B, s, K, h)
            if (Gen_eddsa.generalized_solve_commitment(R_calc_bytes, K_point, null,
                s_scalar, eddsa_25519_pubkey_bytes, h_scalar) != 0)
                return -1;

            // Rv = solve_commitment(Bv, s, Kv, h)
            if (Gen_eddsa.generalized_solve_commitment(Rv_calc_bytes, Kv_point, Bv_point,
                s_scalar, Kv_bytes, h_scalar) != 0)
                return -1;

            Ge_scalarmult_cofactor.ge_scalarmult_cofactor(cK_point, K_point);
            Ge_scalarmult_cofactor.ge_scalarmult_cofactor(cKv_point, Kv_point);
            if (Ge_isneutral.ge_isneutral(cK_point) != 0 || Ge_isneutral.ge_isneutral(cKv_point) != 0 || Ge_isneutral.ge_isneutral(Bv_point) != 0)
                return -1;

            // labelset3 = add_label(labels, "3")
            // h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)
            labelset[(int)labelset_len - 1] = Encoding.UTF8.GetBytes("3")[0];
            Bv_bytes.CopyTo(extra);
            Kv_bytes.Slice(0, (int)Gen_constants.POINTLEN).CopyTo(extra.Slice((int)Gen_constants.POINTLEN));
            Rv_calc_bytes.CopyTo(extra.Slice(2 * (int)Gen_constants.POINTLEN));
            if (Gen_eddsa.generalized_challenge(sha512provider, h_calc_scalar,
                labelset, labelset_len,
                extra, 3 * Gen_constants.POINTLEN,
                R_calc_bytes, eddsa_25519_pubkey_bytes,
                M_buf, Gen_constants.MSTART, msg_len) != 0)
                return -1;

            // if bytes_equal(h, h')
            if (Crypto_verify_32.crypto_verify_32(h_scalar, h_calc_scalar) != 0)
                return -1;

            // labelset4 = add_label(labels, "4")
            // v = hash(labelset4 || c*Kv)
            labelset[(int)labelset_len - 1] = Encoding.UTF8.GetBytes("4")[0];
            if (generalized_calculate_vrf_output(sha512provider, vrf_out, labelset, labelset_len, cKv_point) != 0)
                return -1;

            return 0;
        }
    }
}
