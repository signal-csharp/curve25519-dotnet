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
        /// Copy bytes from _in to bufptr
        /// </summary>
        /// <param name="bufptr">The buffer to copy to</param>
        /// <param name="bufend">The entire buffer bufptr is pointed into, shouldn't be null.</param>
        /// <param name="_in">The buffer to copy from</param>
        /// <param name="in_len">The length of _in</param>
        /// <returns>bufptr pointing in_len bytes forward</returns>
        public static Span<byte> buffer_add(Span<byte> bufptr, ReadOnlySpan<byte> bufend,
            ReadOnlySpan<byte> _in, uint in_len)
        {
            int count = 0;

            if (bufptr == null || bufend == null /*|| bufptr > bufend*/)
                return null;
            if (_in == null && in_len != 0)
                return null;
            if (in_len > bufptr.Length)
                return null;

            for (count = 0; count < in_len; count++)
            {
                if (count > bufptr.Length)
                    return null;
                bufptr[count] = _in[count];
            }
            return bufptr.Slice((int)in_len);
        }

        public static Span<byte> buffer_pad(ReadOnlySpan<byte> buf, Span<byte> bufptr, ReadOnlySpan<byte> bufend)
        {
            int count = 0;
            uint pad_len = 0;

            if (buf == null || bufptr == null || bufend == null /*|| bufptr >= bufend*/ || buf.Length < bufptr.Length)
                return null;

            pad_len = (uint)(Gen_constants.BLOCKLEN - ((buf.Length - bufptr.Length) % Gen_constants.BLOCKLEN)) % Gen_constants.BLOCKLEN;
            if (pad_len > bufptr.Length)
                return null;

            for (count = 0; count < pad_len; count++)
            {
                if (count > bufptr.Length)
                    return null;
                bufptr[count] = 0;
            }
            return bufptr.Slice((int)pad_len);
        }

        public static int labelset_new(Span<byte> labelset, ref uint labelset_len, uint labelset_maxlen,
            ReadOnlySpan<byte> protocol_name, byte protocol_name_len,
            ReadOnlySpan<byte> customization_label, byte customization_label_len)
        {
            Span<byte> bufptr = null;
            if (labelset == null || labelset_maxlen < 3 + protocol_name_len + customization_label_len)
                return -1;

            bufptr = labelset;
            bufptr[0] = 2;
            bufptr = bufptr.Slice(1);
            bufptr[0] = protocol_name_len;
            bufptr = bufptr.Slice(1);
            bufptr = buffer_add(bufptr, labelset, protocol_name, protocol_name_len);
            if (bufptr != null && bufptr.Length < labelset.Length + labelset_maxlen)
            {
                bufptr[0] = customization_label_len;
                bufptr = bufptr.Slice(1);
            }
            bufptr = buffer_add(bufptr, labelset, customization_label, customization_label_len);
            if (bufptr != null)
            {
                // need to manually compute labelset_len because we can't use pointer math in C#
                labelset_len = 2u + protocol_name_len + 1u + customization_label_len;
                return 0;
            }
            return -1;
        }

        public static int labelset_add(Span<byte> labelset, ref uint labelset_len, uint labelset_maxlen,
            ReadOnlySpan<byte> label, byte label_len)
        {
            if (labelset_len + label_len > labelset_maxlen)
                return -1;
            if (labelset_len < 1 || labelset_maxlen < 1 || label_len < 1)
                return -1;
            labelset[0] += 1;
            labelset[(int)labelset_len] = label_len;
            label.CopyTo(labelset.Slice((int)labelset_len + 1));
            labelset_len += 1u + label_len;
            return 0;
        }

        public static int labelset_validate(ReadOnlySpan<byte> labelset, uint labelset_len)
        {
            byte num_labels = 0;
            byte count = 0;
            uint offset = 0;

            if (labelset == null)
                return -1;
            if (labelset_len < 3)
                return -1;

            num_labels = labelset[0];
            offset = 1;
            for (count = 0; count < num_labels; count++)
            {
                offset += 1u + labelset[(int)offset];
                if (offset > labelset_len)
                    return -1;
            }
            if (offset != labelset_len)
                return -1;
            return 0;
        }

        public static bool labelset_is_empty(ReadOnlySpan<byte> labelset, uint labelset_len)
        {
            if (labelset_len != 3)
                return false;
            return true;
        }
    }
}
