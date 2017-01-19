namespace curve25519.bc_crypto
{
    public interface IDigest
    {
        /// <summary>
        /// return the algorithm name
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// return the size, in bytes, of the digest produced by this message digest.
        /// </summary>
        /// <returns>the size, in bytes, of the digest produced by this message digest.</returns>
        int GetDigestSize();

        /// <summary>
        /// return the size, in bytes, of the internal buffer used by this digest.
        /// </summary>
        /// <returns>the size, in bytes, of the internal buffer used by this digest.</returns>
        int GetByteLength();

        /// <summary>
        /// update the message digest with a single byte.
        /// </summary>
        /// <param name="input">the input byte to be entered.</param>
        void Update(byte input);

        /// <summary>
        /// update the message digest with a block of bytes.
        /// </summary>
        /// <param name="input">the byte array containing the data.</param>
        /// <param name="inOff">the offset into the byte array where the data starts.</param>
        /// <param name="length">the length of the data.</param>
        void BlockUpdate(byte[] input, int inOff, int length);

        /// <summary>
        /// Close the digest, producing the final digest value. The doFinal
        /// call leaves the digest reset.
        /// </summary>
        /// <param name="output">the array the digest is to be copied into.</param>
        /// <param name="outOff">the offset into the out array the digest is to start at.</param>
        /// <returns></returns>
        int DoFinal(byte[] output, int outOff);

        /// <summary>
        /// reset the digest back to it's initial state.
        /// </summary>
        void Reset();
    }
}
