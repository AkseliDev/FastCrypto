using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace FastCrypto;

/// <summary>
/// Isaac Random Number Generator Cipher
/// 
/// <para>Original author: Bob Jenkins</para>
/// <para>Converted to C# and optimized by AkseliDev</para>
/// </summary>
public class IsaacRandom {

	/// <summary>
	/// The golden ratio.
	/// </summary>
	private const uint GoldenRatio = 0x9e3779b9;

	/// <summary>
	/// The log of the size of the result and state arrays.
	/// </summary>
	private const int LogSize = sizeof(long);

	/// <summary>
	/// The size of the result and states arrays.
	/// </summary>
	private const int Size = 1 << LogSize;

	/// <summary>
	/// A mask for pseudo-random lookup.
	/// </summary>
	private const int Mask = Size - 1 << 2;

	/// <summary>
	/// The size in bytes
	/// </summary>
	private const int ByteSize = Size * sizeof(int);

	/// <summary>
	/// The results given to the user.
	/// </summary>
	private readonly uint[] _results;

	/// <summary>
	/// The internal state.
	/// </summary>
	private readonly uint[] _state;


	/// <summary>
	/// The count through the results in the results array.
	/// </summary>
	private int _count = ByteSize;

	/// <summary>
	/// The accumulator.
	/// </summary>
	private uint _accumulator;

	/// <summary>
	/// The last result.
	/// </summary>
	private uint _last;

	/// <summary>
	/// The counter.
	/// </summary>
	private uint _counter;

	/// <summary>
	/// Creates the random number generator with the specified seed.
	/// </summary>
	/// <param name="seed">The seed.</param>
	public IsaacRandom(int[] seed) {
		_results = new uint[Size];
		_state = new uint[Size];
		Array.Copy(seed, 0, _results, 0, Math.Min(seed.Length, _results.Length));
		Init();
	}

	/// <summary>
	/// Generates 256 results.
	/// </summary>
	[SkipLocalsInit]
	private void Isaac() {

		// _state and _results are never null
		ref uint statePtr = ref MemoryMarshal.GetArrayDataReference(_state);
		ref uint resultsPtr = ref MemoryMarshal.GetArrayDataReference(_results);

		uint i, j, x, y;


		uint last = _last;
		uint accumulator = _accumulator;

		last += ++_counter;

		/**
		 * Pointer indexing faster than array indexing because bounds check can be skipped
		 * 
		 */

		for (i = 0, j = Size / 2; i < Size / 2;) {
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator << 13)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator >> 6)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator << 2)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator >> 16)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
		}
		for (j = 0; j < Size / 2;) {
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator << 13)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator >> 6)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator << 2)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
			x = Unsafe.Add(ref statePtr, i);
			accumulator = (accumulator ^ (accumulator >> 16)) + Unsafe.Add(ref statePtr, j++);
			Unsafe.Add(ref statePtr, i) = y = Unsafe.Add(ref statePtr, (x & Mask) >> 2) + accumulator + last;
			Unsafe.Add(ref resultsPtr, i++) = last = Unsafe.Add(ref statePtr, (y >> LogSize & Mask) >> 2) + x;
		}

		_last = last;
		_accumulator = accumulator;
	}

	/// <summary>
	/// Initializes this random number generator.
	/// </summary>
	private void Init() {

		ref uint statePtr = ref MemoryMarshal.GetArrayDataReference(_state);
		ref uint resultsPtr = ref MemoryMarshal.GetArrayDataReference(_results);

		int i;
		uint a, b, c, d, e, f, g, h;
		a = b = c = d = e = f = g = h = GoldenRatio;

		for (i = 0; i < 4; ++i) {
			a ^= b << 11;
			d += a;
			b += c;
			b ^= c >> 2;
			e += b;
			c += d;
			c ^= d << 8;
			f += c;
			d += e;
			d ^= e >> 16;
			g += d;
			e += f;
			e ^= f << 10;
			h += e;
			f += g;
			f ^= g >> 4;
			a += f;
			g += h;
			g ^= h << 8;
			b += g;
			h += a;
			h ^= a >> 9;
			c += h;
			a += b;
		}

		for (i = 0; i < Size; i += 8) {
			a += Unsafe.Add(ref resultsPtr, i);
			b += Unsafe.Add(ref resultsPtr, i + 1);
			c += Unsafe.Add(ref resultsPtr, i + 2);
			d += Unsafe.Add(ref resultsPtr, i + 3);
			e += Unsafe.Add(ref resultsPtr, i + 4);
			f += Unsafe.Add(ref resultsPtr, i + 5);
			g += Unsafe.Add(ref resultsPtr, i + 6);
			h += Unsafe.Add(ref resultsPtr, i + 7);

			a ^= b << 11;
			d += a;
			b += c;
			b ^= c >> 2;
			e += b;
			c += d;
			c ^= d << 8;
			f += c;
			d += e;
			d ^= e >> 16;
			g += d;
			e += f;
			e ^= f << 10;
			h += e;
			f += g;
			f ^= g >> 4;
			a += f;
			g += h;
			g ^= h << 8;
			b += g;
			h += a;
			h ^= a >> 9;
			c += h;
			a += b;
			Unsafe.Add(ref statePtr, i) = a;
			Unsafe.Add(ref statePtr, i + 1) = b;
			Unsafe.Add(ref statePtr, i + 2) = c;
			Unsafe.Add(ref statePtr, i + 3) = d;
			Unsafe.Add(ref statePtr, i + 4) = e;
			Unsafe.Add(ref statePtr, i + 5) = f;
			Unsafe.Add(ref statePtr, i + 6) = g;
			Unsafe.Add(ref statePtr, i + 7) = h;
		}

		for (i = 0; i < Size; i += 8) {
			a += Unsafe.Add(ref statePtr, i);
			b += Unsafe.Add(ref statePtr, i + 1);
			c += Unsafe.Add(ref statePtr, i + 2);
			d += Unsafe.Add(ref statePtr, i + 3);
			e += Unsafe.Add(ref statePtr, i + 4);
			f += Unsafe.Add(ref statePtr, i + 5);
			g += Unsafe.Add(ref statePtr, i + 6);
			h += Unsafe.Add(ref statePtr, i + 7);
			a ^= b << 11;
			d += a;
			b += c;
			b ^= c >> 2;
			e += b;
			c += d;
			c ^= d << 8;
			f += c;
			d += e;
			d ^= e >> 16;
			g += d;
			e += f;
			e ^= f << 10;
			h += e;
			f += g;
			f ^= g >> 4;
			a += f;
			g += h;
			g ^= h << 8;
			b += g;
			h += a;
			h ^= a >> 9;
			c += h;
			a += b;
			Unsafe.Add(ref statePtr, i) = a;
			Unsafe.Add(ref statePtr, i + 1) = b;
			Unsafe.Add(ref statePtr, i + 2) = c;
			Unsafe.Add(ref statePtr, i + 3) = d;
			Unsafe.Add(ref statePtr, i + 4) = e;
			Unsafe.Add(ref statePtr, i + 5) = f;
			Unsafe.Add(ref statePtr, i + 6) = g;
			Unsafe.Add(ref statePtr, i + 7) = h;
		}

		Isaac();
	}

	/// <summary>
	/// Processes a block of bytes using the results generated by isaac RNG
	/// </summary>
	/// <param name="input"></param>
	/// <param name="offset"></param>
	/// <param name="count"></param>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	public void ProcessBytes(byte[] input, int offset, int count) {

		if ((count + offset) > input.Length) {
			throw new ArgumentOutOfRangeException();
		}

		ref byte resultsPtr = ref Unsafe.As<uint, byte>(ref MemoryMarshal.GetArrayDataReference(_results));
		ref byte inputPtr = ref MemoryMarshal.GetArrayDataReference(input);
		ref byte endPtr = ref Unsafe.Add(ref inputPtr, count);

		int isaacCount = _count;

		/**
		 * Loop until isaac has to be cycled instead of checking on every iteration
		 */

		while (Unsafe.IsAddressLessThan(ref inputPtr, ref endPtr)) {

			int length = Math.Min(count, count - offset);
			int i = 0;

			// unrolled loop
			for (; i < length - 8; i += 8) {
				Unsafe.Add(ref inputPtr, i) += Unsafe.Add(ref resultsPtr, isaacCount - 1);
				Unsafe.Add(ref inputPtr, i + 1) += Unsafe.Add(ref resultsPtr, isaacCount - 2);
				Unsafe.Add(ref inputPtr, i + 2) += Unsafe.Add(ref resultsPtr, isaacCount - 3);
				Unsafe.Add(ref inputPtr, i + 3) += Unsafe.Add(ref resultsPtr, isaacCount - 4);
				Unsafe.Add(ref inputPtr, i + 4) += Unsafe.Add(ref resultsPtr, isaacCount - 5);
				Unsafe.Add(ref inputPtr, i + 5) += Unsafe.Add(ref resultsPtr, isaacCount - 6);
				Unsafe.Add(ref inputPtr, i + 6) += Unsafe.Add(ref resultsPtr, isaacCount - 7);
				Unsafe.Add(ref inputPtr, i + 7) += Unsafe.Add(ref resultsPtr, isaacCount - 8);
				isaacCount -= 8;
			}
			for (; i < length; i++) {
				Unsafe.Add(ref inputPtr, i) += Unsafe.Add(ref resultsPtr, --isaacCount);
			}
			inputPtr = ref Unsafe.Add(ref inputPtr, length);
			offset += length;
			if (isaacCount == 0) {
				Isaac();
				isaacCount = ByteSize;
			}
		}

		_count = isaacCount;
	}

}