from __future__ import annotations
import argparse
import hmac as _hmac
import logging
import os
import signal
import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.kdf import derive_keys
from scripts.socket_utils import send_framed, recv_framed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_Q_LEN = 65
_NONCE_LEN = 16
_MAC_LEN = 32


def _handle_connection(conn: socket.socket) -> None:
    try:
        msg1 = recv_framed(conn)
        if len(msg1) != _Q_LEN + _NONCE_LEN:
            logger.warning("Msg1 wrong length: %d", len(msg1))
            return

        q_c_bytes = msg1[:_Q_LEN]
        n_c = msg1[_Q_LEN:]

        server_key = ec.generate_private_key(SECP256R1())
        server_pub = server_key.public_key()
        q_s_bytes = server_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

        n_s = os.urandom(_NONCE_LEN)

        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), q_c_bytes)
        shared_secret = server_key.exchange(ECDH(), client_pub)
        k_enc, k_mac = derive_keys(shared_secret, n_c, n_s, "laid")

        mac_s = _hmac.new(k_mac, q_c_bytes + n_c + q_s_bytes + n_s, "sha256").digest()
        send_framed(conn, q_s_bytes + n_s + mac_s)

        msg3 = recv_framed(conn)
        if len(msg3) != _MAC_LEN:
            logger.warning("Msg3 wrong length: %d", len(msg3))
            return

        mac_c_expected = _hmac.new(k_mac, q_s_bytes + n_s + q_c_bytes + n_c, "sha256").digest()
        if not _hmac.compare_digest(msg3, mac_c_expected):
            logger.warning("Msg3 MAC verification failed")
            return

        logger.info("Handshake complete")
    except Exception as exc:
        logger.error("Connection error: %s", exc)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="LAID ECC auth server")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args()

    def _sigint(*_):
        print("Server stopping")
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", args.port))
        srv.listen(16)
        logger.info("ECC auth server listening on 127.0.0.1:%d", args.port)
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                break
            logger.info("Connection from %s", addr)
            _handle_connection(conn)


if __name__ == "__main__":
    main()
