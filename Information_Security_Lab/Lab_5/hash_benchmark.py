"""
- Generates a dataset of N random strings (default 100, allowed 50-100).
- Computes MD5, SHA-1 and SHA-256 hashes for each string while measuring
  total and per-item computation time.
- Detects collisions (different inputs producing same hash) and reports them.

Usage:
    python hash_benchmark.py --count 75 --min-len 8 --max-len 32 --seed 42

Notes:
- Collision detection here is an exact match on the hex digest. For strong
  hash functions like SHA-256, collisions in small random datasets are
  extraordinarily unlikely; this demo shows the mechanics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import string
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple


def generate_random_strings(count: int, min_len: int = 8, max_len: int = 32, seed: int | None = None) -> List[str]:
    """Generate `count` pseudorandom ASCII strings with lengths in [min_len, max_len].

    Args:
        count: Number of strings to produce.
        min_len, max_len: Inclusive bounds for the random string length.
        seed: Optional RNG seed for reproducibility.

    Returns:
        List[str]: Generated strings.
    """
    if seed is not None:
        random.seed(seed)

    alphabet = string.ascii_letters + string.digits
    out = []
    for _ in range(count):
        L = random.randint(min_len, max_len)
        out.append(''.join(random.choices(alphabet, k=L)))
    return out


def time_hash_algorithm(strings: Iterable[str], algorithm: str) -> Tuple[Dict[str, str], float]:
    """Compute digests for each input string using the named algorithm and time it.

    Args:
        strings: Iterable of input strings.
        algorithm: One of 'md5', 'sha1', 'sha256'.

    Returns:
        (mapping, elapsed_seconds)
        mapping: dict mapping original string -> hex digest
        elapsed_seconds: wall-clock time to compute all digests
    """
    algo = algorithm.lower()
    if algo not in ('md5', 'sha1', 'sha256'):
        raise ValueError('Unsupported algorithm: ' + algorithm)

    mapping: Dict[str, str] = {}
    start = time.perf_counter()
    for s in strings:
        b = s.encode('utf-8')
        if algo == 'md5':
            h = hashlib.md5(b).hexdigest()
        elif algo == 'sha1':
            h = hashlib.sha1(b).hexdigest()
        else:
            h = hashlib.sha256(b).hexdigest()
        mapping[s] = h
    elapsed = time.perf_counter() - start
    return mapping, elapsed


def detect_collisions(mapping: Dict[str, str]) -> Dict[str, List[str]]:
    """Detect collisions in a mapping from input->digest.

    Returns a dict mapping digest -> list of inputs that produced it, only
    including entries where len(list) > 1.
    """
    reverse: Dict[str, List[str]] = defaultdict(list)
    for inp, digest in mapping.items():
        reverse[digest].append(inp)

    collisions = {d: ins for d, ins in reverse.items() if len(ins) > 1}
    return collisions


def run_benchmark(count: int = 100, min_len: int = 8, max_len: int = 32, seed: int | None = None, save_json: str | None = None):
    if not (50 <= count <= 100):
        raise ValueError('count must be between 50 and 100')

    print(f'Generating {count} random strings (len {min_len}-{max_len}), seed={seed}')
    data = generate_random_strings(count, min_len, max_len, seed)

    results = {}

    for algo in ('md5', 'sha1', 'sha256'):
        mapping, elapsed = time_hash_algorithm(data, algo)
        collisions = detect_collisions(mapping)

        results[algo] = {
            'elapsed_seconds': elapsed,
            'per_item_seconds': elapsed / len(data) if data else 0,
            'throughput_items_per_second': (len(data) / elapsed) if elapsed > 0 else None,
            'num_items': len(data),
            'num_unique_hashes': len(set(mapping.values())),
            'num_collisions': len(collisions),
            'collisions': collisions,
        }

        print(f"{algo.upper():6} : time={elapsed:.6f}s, avg={results[algo]['per_item_seconds']:.6f}s/item, "
              f"throughput={results[algo]['throughput_items_per_second']:.0f} items/s, "
              f"collisions={results[algo]['num_collisions']}")

    if save_json:
        with open(save_json, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print('Saved results to', save_json)

    return results


def parse_args():
    p = argparse.ArgumentParser(description='Hash function benchmarking and collision detection')
    p.add_argument('--count', type=int, default=100, help='Number of random strings (50-100)')
    p.add_argument('--min-len', type=int, default=8, help='Minimum string length')
    p.add_argument('--max-len', type=int, default=32, help='Maximum string length')
    p.add_argument('--seed', type=int, default=None, help='RNG seed (optional)')
    p.add_argument('--save-json', type=str, default=None, help='Save detailed results to JSON file')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    run_benchmark(count=args.count, min_len=args.min_len, max_len=args.max_len, seed=args.seed, save_json=args.save_json)
