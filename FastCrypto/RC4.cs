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

        // StateLength should always be dividable by 8
        private const int StateLength = 256;

        private byte[] _state;
        private byte[] _key;
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
        public void ProcessBytes(byte[] input, int offset, int length) {

            if (length + offset > input.Length) {
                throw new ArgumentOutOfRangeException("input buffer is too short");
            }

            unsafe {
                // pin both, the engine state and input
                // to local fixed buffers
                fixed (byte* engine = _state, pointer = input) {

                    byte* ptr = (pointer + offset);

                    // create local copies of the x,y states
                    // because accessing locals is faster
                    int x = _x;
                    int y = _y;

                    // reverse loop is faster because the length needs to be read only once
                    for (int i = length; i > 0; i--) {

                        // optimized operations
                        // removed unnecessary array accesses

                        byte xState = engine[x = (x + 1) & 0xff];
                        byte yState = engine[y = (xState + y) & 0xff];

                        engine[x] = yState;
                        engine[y] = xState;

                        *ptr ^= engine[(yState + xState) & 0xff];

                        // point to the next index
                        ptr++;
                    }

                    // return the state
                    _x = x;
                    _y = y;
                }
            }
        }

        /// <summary>
        /// Sets the state to a given key
        /// </summary>
        /// <param name="keyBytes"></param>
        private void SetKey(byte[] keyBytes) {
            
            _x = _y = 0;

            // loop unrolling
            for (int i = 0; i < StateLength / 8; i += 8) {
                _state[i] = (byte)i;
                _state[i + 1] = (byte)(i + 1);
                _state[i + 2] = (byte)(i + 2);
                _state[i + 3] = (byte)(i + 3);
                _state[i + 4] = (byte)(i + 4);
                _state[i + 5] = (byte)(i + 5);
                _state[i + 6] = (byte)(i + 6);
                _state[i + 7] = (byte)(i + 7);
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
