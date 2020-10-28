from .block import Block
from .tx import Tx, TxIn, OutPoint, TxOut
from .script import script_int_to_bytes
from .util import bits_to_target

import binascii


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
    outpoint = OutPoint(
        tx_hash=bytes([0]) * 32,
        index=4294967295  # この数値はuint32における最大値。通常の送金等では使われることはまずないだろうということで使われていると推測
    )
    first_bits = (0x1d00ffff).to_bytes(4, "little")  # リトルエンディアンで格納されるため
    ascii_msg = []
    for s in msg:
        ascii_msg.append(ord(s))
    tx_in = TxIn(
        outpoint=outpoint,
        script_sig=len(first_bits).to_bytes(1, "little") +  # 文字列(何かしらの数値も含む)を入れるときはまず長さを入れる
                   first_bits +  # bitsを挿入
                   b"\x01\x04" +  # Bitcoinではなぜか"4"という数字が文字列として挿入されているため、それに従い長さと文字列本体を挿入
                   script_int_to_bytes(
                       len(msg)) +  # ジェネシスメッセージの長さを挿入。Bitcoin Scriptに従い、0x4d以上の長さであれば大きさに応じてPUSHDATAが付与される
                   bytes(ascii_msg),  # ジェネシスメッセージをASCIIで挿入
        sequence=0xffffffff  # デフォルトが最大値。特に何もなければこのデフォルト値を使う。
    )
    tx_out = TxOut(
        value=reward,  # マイニング報酬も設定値をそのまま代入
        script_pubkey=binascii.a2b_hex(
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
        )  # 本来、script pubkeyに代入する値も自分で生成すべきなのだが、手間がかかるのでBitcoinのものを丸ごと流用している。
    )
    genesis_tx = Tx(
        version=1,  # 現在BitcoinにTxのVersionは1と2があるが、特別な機能(=SegWit等)を使わない限り1でよい
        tx_ins=[tx_in],  # tx_inをリストにして代入
        tx_outs=[tx_out],  # tx_inと一緒
        locktime=0  # locktimeは特に必要がないので0を代入
    )

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

    # bitsは32bytesのtargetに変換され、使用される。使用方法は後程
    target = bits_to_target(bits)

    for i in range(0xffffffff):
        # マイニングとは、生成するブロックのハッシュがあらかじめ設定されたtargetよりも小さくなるようなnonceを探すことである。
        # というわけで、全探索的にnonceを探す。
        block.nonce = i  # nonceを設定
        block_hash = int.from_bytes(block.block_hash(), "big")  # ブロックのハッシュを整数に直す
        print(block.nonce, target, block_hash)
        if target > block_hash:
            break

    return block
