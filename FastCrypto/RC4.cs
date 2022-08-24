using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastCrypto {

    /// <summary>
    /// Optimized RC4 Cipher for processing byte arrays
    /// </summary>
    public class RC4 {

        private const int StateLength = 256;

        private readonly byte[] _state;
        private readonly byte[] _key;
        private int _x;
        private int _y;

        public RC4(byte[] key) {
            _key = key;
            _state = new byte[StateLength];
            SetKey(key);
        }

        /// <summary>
        /// Resets the cipher to its original state
        /// </summary>
        public void Reset() {
            SetKey(_key);
        }

        /// <summary>
        /// Encrypts a block of bytes
        /// </summary>
        /// <param name="input">The block of bytes to encrypt</param>
        /// <param name="length">The amount of bytes to encrypt</param>
        /// <param name="offset">The offset in the buffer where to start encrypting</param>
        /// <exception cref="ArgumentOutOfRangeException">If the input buffer is too short</exception>
        public void ProcessBytes(byte[] input, int offset, int length) => ProcessBytes(input.AsSpan(offset, length));

        /// <summary>
        /// Encrypts a block of bytes
        /// </summary>
        /// <param name="input">The block of bytes to encrypt</param>
        /// <exception cref="ArgumentOutOfRangeException">If the input buffer is too short</exception>
        public void ProcessBytes(Span<byte> input) {

            /**
             * Using a span is faster than a fixed block + pointers because of pinning overhead, 
             * also its not unsafe which is a plus
             */

            // create local copies of the x,y states
            int x = _x;
            int y = _y;

            // if we create a span from 0 to StateLength (256)
            // the JIT compiler can remove bounds checks
            Span<byte> engine = _state.AsSpan(0, StateLength);

            // array bounds checks can be removed
            for (int i = 0; i < input.Length; i++) {

                // optimized operations
                // removed unnecessary array accesses

                byte xState = engine[x = (x + 1) & 0xff];
                byte yState = engine[y = (xState + y) & 0xff];

                engine[x] = yState;
                engine[y] = xState;

                input[i] ^= engine[(yState + xState) & 0xff];


            }

            // return the state
            _x = x;
            _y = y;

        }

        /// <summary>
        /// Sets the state to a given key
        /// </summary>
        /// <param name="keyBytes"></param>
        private void SetKey(byte[] keyBytes) {
            
            _x = _y = 0;

            // not worth to unroll
            for (int i = 0; i < _state.Length; i++) {
                _state[i] = (byte)i;
            }

            for (int i = 0, j = 0, k = 0; i < StateLength; i++) {
                byte tmp = _state[i];
                _state[i] = _state[k = ((keyBytes[j] & 0xff) + tmp + k) & 0xff];
                _state[k] = tmp;
                j = (j + 1) % keyBytes.Length;
            }
        }
    }
}
