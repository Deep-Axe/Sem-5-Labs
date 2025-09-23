"""Simple 32-bit hash function implementation.

This implements a djb2-like algorithm with an extra mixing step.
Algorithm (per-character):
 1. start with h = 5381
 2. h = h * 33 + ord(char)
 3. perform an additional mixing step using XOR with a right-shifted
	version of the intermediate value to spread high bits into low bits
 4. keep h within 32 bits by masking with 0xFFFFFFFF

The function returns an unsigned 32-bit integer.
"""

from __future__ import annotations

def hash_fn(s: str) -> int:
	"""Compute a 32-bit hash for the input string.

	Args:
		s: Input string to hash.

	Returns:
		int: Unsigned 32-bit hash value (0 <= value <= 0xFFFFFFFF).
	"""
	# Initial value specified in the prompt
	h = 5381

	for ch in s:
		# Multiply by 33 and add the ASCII/Unicode codepoint of the char.
		# Using the typical djb2 step: h = h * 33 + c
		h = (h * 33 + ord(ch)) & 0xFFFFFFFF

		# Additional bitwise mixing to help spread entropy from higher
		# to lower bits. XOR with a right-shifted copy is a cheap, common
		# trick that improves avalanche for small inputs.
		h = (h ^ (h >> 16)) & 0xFFFFFFFF

	# Ensure returned value is within 32-bit unsigned range
	return h & 0xFFFFFFFF


def hash_hex(s: str) -> str:
	"""Convenience helper returning the 8-character zero-padded hex form."""
	return f"{hash_fn(s):08X}"


if __name__ == '__main__':
	# Quick demo / smoke test when run as script
	samples = ["", "a", "hello", "The quick brown fox jumps over the lazy dog"]
	for sample in samples:
		print(repr(sample).ljust(45), "->", hash_fn(sample), hash_hex(sample))

