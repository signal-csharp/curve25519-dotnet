using System;

namespace org.whispersystems.curve25519.csharp
{
    public class Gen_labelset
    {
        public static readonly byte[] B_bytes = {
          0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
          0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
          0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
          0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        };

        /// <summary>
        /// Copy bytes from _in to buf starting at index bufptr
        /// </summary>
        /// <param name="buf">The buffer to copy to</param>
        /// <param name="bufptr">The starting copy index</param>
        /// <param name="_in">The buffer to copy from</param>
        /// <param name="in_len">The length of _in</param>
        /// <returns>in_len if bytes were copied, null if there was an error</returns>
        public static int? buffer_add(byte[] buf, int? bufptr,
            byte[] _in, uint in_len)
        {
            if (buf == null || bufptr == null)
                return null;
            if (_in == null && in_len != 0)
                return null;
            if (buf.Length - bufptr < in_len)
                return null;

            if (in_len > 0)
            {
                Array.Copy(_in, 0, buf, bufptr.Value, (int)in_len);
            }
            return (int)in_len;
        }

        public static int? buffer_pad(byte[] buf, int bufstart, int? bufptr, int bufend)
        {
            int count = 0;
            uint pad_len = 0;

            if (buf == null || bufptr == null || bufptr >= bufend || bufptr < bufstart)
                return null;

            pad_len = (uint)(Gen_constants.BLOCKLEN - ((bufptr - bufstart) % Gen_constants.BLOCKLEN)) % Gen_constants.BLOCKLEN;
            if (bufend - bufptr < pad_len)
                return null;

            for (count = 0; count < pad_len; count++)
            {
                if (bufptr >= bufend)
                    return null;
                buf[bufptr.Value] = 0;
                bufptr += 1;
            }
            return (int)pad_len;
        }

        public static int labelset_new(byte[] labelset, ref uint labelset_len, uint labelset_maxlen,
            byte[] protocol_name, byte protocol_name_len,
            byte[] customization_label, byte customization_label_len)
        {
            int? bufptr = 0;

            labelset_len = 0;
            if (labelset == null)
                return -1;
            //if (labelset_len == null)
            //    return -1;
            if (labelset_maxlen > Gen_constants.LABELSETMAXLEN)
                return -1;
            if (labelset_maxlen < 3 + protocol_name_len + customization_label_len)
                return -1;
            if (protocol_name == null && protocol_name_len != 0)
                return -1;
            if (customization_label == null && customization_label_len != 0)
                return -1;
            if (protocol_name_len > Gen_constants.LABELMAXLEN)
                return -1;
            if (customization_label_len > Gen_constants.LABELMAXLEN)
                return -1;

            labelset[bufptr.Value] = 2;
            bufptr += 1;
            labelset[bufptr.Value] = protocol_name_len;
            bufptr += 1;
            bufptr += buffer_add(labelset, bufptr, protocol_name, protocol_name_len);
            if (bufptr != null && bufptr < labelset_maxlen)
            {
                labelset[bufptr.Value] = customization_label_len;
                bufptr += 1;
            }
            bufptr += buffer_add(labelset, bufptr, customization_label, customization_label_len);
            if (bufptr != null && bufptr == 3 + protocol_name_len + customization_label_len)
            {
                labelset_len = (uint)bufptr.Value;
                return 0;
            }
            return -1;
        }

        public static int labelset_add(byte[] labelset, ref uint labelset_len, uint labelset_maxlen,
            byte[] label, byte label_len)
        {
            int? bufptr = 0;
            //if (labelset_len == null)
            //    return -1;
            if (labelset_len > Gen_constants.LABELSETMAXLEN || labelset_maxlen > Gen_constants.LABELSETMAXLEN)
                return -1;
            if (labelset_len >= labelset_maxlen || labelset_len + label_len + 1 > labelset_maxlen)
                return -1;
            if (labelset_len < 3 || labelset_maxlen < 4)
                return -1;
            if (label_len > Gen_constants.LABELMAXLEN)
                return -1;

            labelset[0] += 1;
            labelset[(int)labelset_len] = label_len;
            bufptr = (int)labelset_len + 1;
            bufptr += buffer_add(labelset, bufptr, label, label_len);
            if (bufptr == null)
                return -1;
            if (bufptr >= labelset_maxlen)
                return -1;
            if (bufptr != labelset_len + 1 + label_len)
                return -1;

            labelset_len += 1u + label_len;
            return 0;
        }

        public static int labelset_validate(byte[] labelset, uint labelset_len)
        {
            byte num_labels = 0;
            byte count = 0;
            uint offset = 0;
            byte label_len = 0;

            if (labelset == null)
                return -1;
            if (labelset_len < 3 || labelset_len > Gen_constants.LABELSETMAXLEN)
                return -1;

            num_labels = labelset[0];
            offset = 1;
            for (count = 0; count < num_labels; count++)
            {
                label_len = labelset[offset];
                if (label_len > Gen_constants.LABELMAXLEN)
                    return -1;
                offset += 1u + label_len;
                if (offset > labelset_len)
                    return -1;
            }
            if (offset != labelset_len)
                return -1;
            return 0;
        }

        public static bool labelset_is_empty(byte[] labelset, uint labelset_len)
        {
            if (labelset_len != 3)
                return false;
            return true;
        }
    }
}
