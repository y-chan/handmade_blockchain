from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Union

from hashlib import sha256

from .tx import Tx
from .util import int_to_bytes

import binascii


@dataclass
class Block:
    version: int
    hash_prev_block: bytes
    hash_merkle_root: bytes
    time: int
    bits: int
    nonce: int
    transactions: List[Tx]

    @classmethod
    def from_dict(cls, block: Dict, block_hash: Union[str, bytes] = None) -> "Block":
        shaped_block = {}

        data_list: List[Tuple[str, type]] = [
            ("version", int),
            ("hash_prev_block", str),
            ("hash_merkle_root", str),
            ("time", int),
            ("bits", int),
            ("nonce", int),
            ("transactions", list)
        ]

        for data in data_list:
            one_of_block_data = block.get(data[0])
            shaped_block[data[0]] = one_of_block_data
            if one_of_block_data is not None and data[1] == str:
                shaped_block[data[0]] = binascii.a2b_hex(one_of_block_data)[::-1]
            elif one_of_block_data is not None and data[1] == list:
                shaped_block[data[0]] = []
                for tx in one_of_block_data:
                    shaped_block[data[0]].append(Tx.from_dict(tx))

        block = cls(**shaped_block)

        if block_hash:
            block_hash_by_dict = block.block_hash()
            if isinstance(block_hash, str):
                block_hash = binascii.a2b_hex(block_hash)

            if block_hash[::-1] != block_hash_by_dict:
                raise Exception("Block data is invalid!")

        return block

    def as_dict(self) -> Dict:
        result = asdict(self)
        result["hash_prev_block"] = result["hash_prev_block"][::-1].hex()
        result["hash_merkle_root"] = result["hash_merkle_root"][::-1].hex()
        txs = result["transactions"]
        result["transactions"] = []
        for tx in txs:
            result["transactions"].append(tx.as_dict())
        return result

    def as_hex(self) -> str:
        return self.as_bin().hex()

    def _as_bin(self) -> bytes:
        """
        ブロックハッシュの元となる部分だけを切り出したもの
        バージョン(little、4bytes)、前ブロックのハッシュ(little)、マークルルート(little)、時間(little、4bytes)、
        bits(難易度のやつ、little、4bytes)、nonce(little、4bytes)で構成される
        """
        block_bin = self.version.to_bytes(4, byteorder="little")
        block_bin += self.hash_prev_block
        block_bin += self.hash_merkle_root
        block_bin += self.time.to_bytes(4, byteorder="little")
        block_bin += self.bits.to_bytes(4, byteorder="little")
        block_bin += self.nonce.to_bytes(4, byteorder="little")
        return block_bin

    def as_bin(self) -> bytes:
        """
        生のブロックはバージョン(little、4bytes)、前ブロックのハッシュ(little)、マークルルート(little)、時間(little、4bytes)、
        bits(難易度のやつ、little、4bytes)、nonce(little、4bytes)、
        transaction count(1byte、254を超える場合はBitcoin ScriptのPUSHDATAと似た扱い)
        transactions(transaction count分のtransactionがざっと並ぶ)という、以上の要素で成り立つ。
        """
        block_bin = self._as_bin()
        tx_len = len(self.transactions)
        block_bin += int_to_bytes(tx_len)
        for tx in self.transactions:
            block_bin += tx

        return block_bin

    def block_hash(self) -> bytes:
        block_bin = self._as_bin()
        return sha256(sha256(block_bin).digest()).digest()

