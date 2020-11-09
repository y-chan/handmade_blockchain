from .block import Block, get_target, load_blocks
from .tx import Tx, TxIn, OutPoint, TxOut
from .script import script_int_to_bytes, script_int_to_bytes_contain_opcode
from .util import bits_to_target
from .address import address_to_script

from time import time as now_time

import binascii
import random


def create_genesis_block(msg: str, time: int, bits: int, reward: int) -> Block:
    """
    ジェネシスブロック(= ブロックチェーンの始まりのブロック)を生成する。
    Bitcoinの場合、ジェネシスブロックにはメッセージ(ジェネシスメッセージと呼ばれる)が混入され、誰でも閲覧可能になっている。
    ここではジェネシスメッセージを msg 変数で定義する。(なお、ASCIIでエンコードされて混入されるので、英数字のみで構成される必要がある)
    versionは適当な値でよいのだが、Bitcoinでは"1"が用いられるため、そのまま利用する。
    ジェネシスブロックのTxInのScriptSigにマイニングの難易度を表すBitsの初期値(0x1d00ffff)とジェネシスメッセージを仕込むが、
    Bitsの初期値を0x1d00ffffに設定するとハッシュの探索に時間がかかりすぎるので、0x1f00ffffを渡してあげるのがオススメ
    """

    # とりあえずジェネシスメッセージを含んだジェネシストランザクションを生成

    first_bits = bits.to_bytes(4, "little")  # リトルエンディアンで格納されるため
    # script_sigの生成
    script_sig = (
            len(first_bits).to_bytes(1, "little") +  # 文字列(何かしらの数値も含む)を入れるときはまず長さを入れる
            first_bits +  # bitsを挿入
            b"\x01\x04" +  # Bitcoinではなぜか"4"という数字が文字列として挿入されているため、それに従い長さと文字列本体を挿入
            script_int_to_bytes(
                len(msg)  # ジェネシスメッセージの長さを挿入。Bitcoin Scriptに従い、0x4d以上の長さであれば大きさに応じてPUSHDATAが付与される
            ) +
            msg.encode("ascii")  # メッセージそのものを挿入
    )

    # script pubkeyの生成
    # 本来、script pubkeyに代入する値も自分で生成すべきなのだが、手間がかかるのでBitcoinのものを丸ごと流用している。
    # また、開業しているが長いからコーディングガイドラインにしたがって改行しただけで特に意味はない
    script_pubkey = binascii.a2b_hex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb"
        "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
    )

    genesis_tx = create_coinbase_tx(script_sig, script_pubkey, reward)

    # 一旦ブロックを作る(nonceは0を設定)
    block = Block(
        version=1,  # versionの説明は上記ですでにされているため省略
        hash_prev_block=bytes([0]) * 32,  # 本来はNULLが代入されているが、簡易的な処理しか実装していないので32bytes分の0を代入
        hash_merkle_root=genesis_tx.tx_hash(),  # 本来merkle root生成機構を通すべきだが、ジェネシスブロック上では無意味なので省略
        time=time,
        bits=bits,
        nonce=0,
        transactions=[genesis_tx]
    )

    # マイニングに移行
    return mining_block(block)


def create_coinbase_tx(script_sig: bytes, script_pubkey: bytes, reward: int) -> Tx:
    outpoint = OutPoint(
        tx_hash=bytes([0]) * 32,
        index=0xffffffff  # この数値はuint32における最大値。通常の送金等では使われることはまずないだろうということで使われていると推測
    )
    tx_in = TxIn(
        outpoint=outpoint,
        script_sig=script_sig,
        sequence=0xffffffff  # デフォルトが最大値。特に何もなければこのデフォルト値を使う。
    )
    tx_out = TxOut(
        value=reward,  # マイニング報酬は設定値をそのまま代入
        script_pubkey=script_pubkey
    )
    coinbase_tx = Tx(
        version=1,  # 現在BitcoinにTxのVersionは1と2があるが、特別な機能(=SegWit等)を使わない限り1でよい
        tx_ins=[tx_in],  # tx_inをリストにして代入
        tx_outs=[tx_out],  # tx_inと一緒
        locktime=0  # locktimeは特に必要がないので0を代入
    )

    return coinbase_tx


def create_block(height: int, receive_address: str) -> Block:
    coinbase_tx = create_coinbase_tx(
        script_sig=script_int_to_bytes_contain_opcode(height)+b"\x00",  # height + OP_0
        script_pubkey=address_to_script(receive_address)
    )

    # 一旦ブロックを作る(nonceは0を設定)
    block = Block(
        version=1,  # versionの説明は上記ですでにされているため省略
        hash_prev_block=bytes([0]) * 32,  # 本来はNULLが代入されているが、簡易的な処理しか実装していないので32bytes分の0を代入
        hash_merkle_root=coinbase_tx.tx_hash(),  # 本来merkle root生成機構を通すべきだが、ジェネシスブロック上では無意味なので省略
        time=int(now_time()),
        bits=get_target(load_blocks()),
        nonce=0,
        transactions=[coinbase_tx]
    )

    # マイニングに移行
    return mining_block(block)


def mining_block(block: Block) -> Block:
    # bitsは32bytesのバイト列に変換され、さらにintのtargetに変換されて使用される。使用方法は後程
    target = bits_to_target(block.bits)

    nonce_found = False
    # 0から探すのではなく、ランダム性をもたせる
    start = random.randint(0, 0xffffffff)

    for i in range(start, 0xffffffff):
        # マイニングとは、生成するブロックのハッシュがあらかじめ設定されたtargetよりも小さくなるようなnonceを探すことである。
        # というわけで、全探索的にnonceを探す。
        block.nonce = i  # nonceを設定
        block_hash = int.from_bytes(block.block_hash(), "big")  # ブロックのハッシュをintに直す
        # targetとblock_hashを比較し、targetがblock_hash以下であれば、マイニング成功(=ブロック生成成功)
        if target > block_hash:
            print("nonce found!", f"nonce = {block.nonce}", f"block hash = 0x%064x" % block_hash)
            nonce_found = True
            break

    # 万が一探索しきっても見つからなければ、再探索する
    if not nonce_found:
        return mining_block(block)
    return block

