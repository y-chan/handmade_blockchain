from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple

from .util import int_to_bytes

from hashlib import sha256

import binascii


@dataclass
class OutPoint:
    tx_hash: bytes
    index: int

    @classmethod
    def from_dict(cls, op_data: Dict) -> "OutPoint":
        shaped_data = {}

        data_list: List[Tuple[str, type]] = [
            ("tx_hash", str),
            ("index", int)
        ]

        for data in data_list:
            one_of_block_data = op_data.get(data[0])
            shaped_data[data[0]] = one_of_block_data
            if one_of_block_data is not None and data[1] == str:
                shaped_data[data[0]] = binascii.a2b_hex(one_of_block_data)

        return cls(**shaped_data)

    def as_dict(self) -> Dict:
        result = asdict(self)
        result["tx_hash"] = result["tx_hash"].hex()
        return result

    def as_hex(self) -> str:
        return self.as_bin().hex()

    def as_bin(self) -> bytes:
        """
        OutPointはその通貨をたどるために使われる情報。どの取引でその通貨が自分のアドレスに入ってきたかを示す値になる。
        なお、マイニングで生成された場合はtx_hashが32bytes分の0で埋められる。
        """
        block_bin = self.tx_hash
        block_bin += self.index.to_bytes(4, "little")
        return block_bin


@dataclass
class TxIn:
    outpoint: OutPoint
    script_sig: bytes
    sequence: int

    @classmethod
    def from_dict(cls, tx_in_data: Dict) -> "TxIn":
        shaped_data = {}

        data_list: List[Tuple[str, type]] = [
            ("outpoint", dict),
            ("script_sig", str),
            ("sequence", int)
        ]

        for data in data_list:
            one_of_block_data = tx_in_data.get(data[0])
            shaped_data[data[0]] = one_of_block_data
            if one_of_block_data is not None and data[1] == str:
                shaped_data[data[0]] = binascii.a2b_hex(one_of_block_data)
            elif data[0] == "outpoint":
                shaped_data[data[0]] = OutPoint.from_dict(one_of_block_data)

        return cls(**shaped_data)

    def as_dict(self) -> Dict:
        result = asdict(self)
        result["outpoint"] = result["outpoint"].as_dict()
        result["script_sig"] = result["script_sig"].hex()
        return result

    def as_hex(self) -> str:
        return self.as_bin().hex()

    def as_bin(self) -> bytes:
        """
        TxInはOutPoint、ScriptSig(Signatureの略)、Sequenceの3つの要素で成り立つ。
        OutPointの詳細はOutPoint Classを参照。
        ScriptSigはOutPointでたどられた通貨を所有していることを証明するための、秘密鍵による署名が入ることが一般的。
        SequenceはCSV(Check Sequence Verify)に使われる。
        """
        block_bin = self.outpoint.as_bin()
        block_bin += int_to_bytes(len(self.script_sig))
        block_bin += self.script_sig
        block_bin += self.sequence.to_bytes(4, "little")
        return block_bin


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes

    @classmethod
    def from_dict(cls, tx_out_data: Dict) -> "TxOut":
        shaped_data = {}

        data_list: List[Tuple[str, type]] = [
            ("value", int),
            ("script_pubkey", str)
        ]

        for data in data_list:
            one_of_block_data = tx_out_data.get(data[0])
            shaped_data[data[0]] = one_of_block_data
            if one_of_block_data is not None and data[1] == str:
                shaped_data[data[0]] = binascii.a2b_hex(one_of_block_data)

        return cls(**shaped_data)

    def as_dict(self) -> Dict:
        result = asdict(self)
        result["script_pubkey"] = result["script_pubkey"].hex()
        return result

    def as_hex(self) -> str:
        return self.as_bin().hex()

    def as_bin(self) -> bytes:
        """
        TxOutはValue、ScriptPubKeyの2つの要素で成り立つ。
        Valueは送金価格を表し、最小単位で示される。
        ScriptPubKeyは送金のためのスクリプトが記述される。(Bitcoin Scriptが用いられるが、複雑なため省略)
        """
        block_bin = self.value.to_bytes(8, "little")
        block_bin += int_to_bytes(len(self.script_pubkey))
        block_bin += self.script_pubkey
        return block_bin


@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int

    @classmethod
    def from_dict(cls, tx_data: Dict) -> "Tx":
        shaped_data = {}

        data_list: List[Tuple[str, type]] = [
            ("version", int),
            ("tx_ins", list),
            ("tx_outs", list),
            ("locktime", int)
        ]

        for data in data_list:
            one_of_block_data = tx_data.get(data[0])
            shaped_data[data[0]] = one_of_block_data
            if one_of_block_data is not None and data[1] == str:
                shaped_data[data[0]] = binascii.a2b_hex(one_of_block_data)
            elif one_of_block_data is not None and data[1] == list:
                shaped_data[data[0]] = []
                if data[0] == "tx_ins":
                    for tx_in in one_of_block_data:
                        shaped_data[data[0]].append(TxIn.from_dict(tx_in))
                if data[0] == "tx_outs":
                    for tx_out in one_of_block_data:
                        shaped_data[data[0]].append(TxOut.from_dict(tx_out))

        return cls(**shaped_data)

    def as_dict(self) -> Dict:
        result = asdict(self)
        tx_ins = result["tx_ins"]
        tx_outs = result["tx_outs"]
        result["tx_ins"] = []
        for tx_in in tx_ins:
            result["tx_ins"].append(tx_in.as_dict())
        for tx_out in tx_outs:
            result["tx_outs"].append(tx_out.as_dict())
        return result

    def as_hex(self) -> str:
        return self.as_bin().hex()

    def as_bin(self) -> bytes:
        """
        Tx(Transaction)はVersion、TxIns(Transaction Inの集まり)、TxOuts(Transaction Outの集まり)、LockTimeで構成される。
        VersionはTransactionが新しい機能に対応しているかなどを判別するうえで有効。ただし、今回のハンドメイドブロックチェーンでは
        1以外のVersion値は用いない。
        TxInsは送金元の情報をまとめたもの。一か所から送金するわけではない場合もあり、複数の送金元から送金できる。
        TxInの中身についてはTxIn Classを参照。
        TxOutsは送金先の情報をまとめたもの。TxInsと同じく、一度に複数の送金先に送金できる。
        TxOutの中身についてはTxOut Classを参照。
        LockTimeは簡単に言えば、設定した時刻まで送金出来ないように制限をかけられる値。0に設定されていれば、LockTimeは無効化される。
        """
        block_bin = self.version.to_bytes(4, "little")
        block_bin += int_to_bytes(len(self.tx_ins))
        for tx_in in self.tx_ins:
            block_bin += tx_in.as_bin()
        block_bin += int_to_bytes(len(self.tx_outs))
        for tx_out in self.tx_outs:
            block_bin += tx_out.as_bin()
        block_bin += self.locktime.to_bytes(4, "little")

        return block_bin

    def tx_hash(self) -> bytes:
        block_bin = self.as_bin()
        return sha256(sha256(block_bin).digest()).digest()
