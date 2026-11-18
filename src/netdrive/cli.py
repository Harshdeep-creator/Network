"""Terminal entry point. `netdrive receive`, `send`, `discover`, `ui`, and the demos."""

from __future__ import annotations

import argparse
import secrets
import socket
import sys
import threading
from pathlib import Path

from netdrive import __version__
from netdrive.demo_mitm import run_demo
from netdrive.discovery import Beacon, discover, parse_hostport
from netdrive.identity import (
    contact_uri,
    identity_path,
    load_contact_secret,
    load_identity,
    parse_contact_uri,
    public_raw,
    reset_identity,
)
from netdrive.contacts import Contacts
from netdrive.crypto import forced_distinct_prefix, rotating_id
from netdrive.webreceiver import write_qr
from netdrive.receiver import Receiver
from netdrive.sender import send_files, send_text
from netdrive.sim.mesh import run_mesh
from netdrive.sim.radio import path_report
from netdrive.webreceiver import WebDrop


def _allow_who(directory: Path, visibility: str):
    """WHO replies. Contacts only answers a matching rotating id. Blocked keys get silence."""

    def allow(data: bytes) -> bool:
        book = Contacts(directory / ".netdrive" / "contacts.json")
        body: dict = {}
        try:
            parsed = __import__("json").loads(data.decode("utf-8"))
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            body = {}
        pk = str(body.get("pk") or "")
        token = str(body.get("rotating") or "")
        if pk and book.is_blocked(pk):
            return False
        if token and book.is_blocked(token):
            return False
        if visibility == "Contacts only":
            if not token:
                return False
            try:
                from netdrive.crypto import recognizes

                return recognizes(load_contact_secret(directory), bytes.fromhex(token))
            except ValueError:
                return False
        return True

    return allow


def _nick(value: str | None) -> str:
    return value or "netdrive-" + secrets.token_hex(2)


def _local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def _cmd_receive(args: argparse.Namespace) -> int:
    nick = _nick(args.nick)
    directory = Path(args.dir)
    receiver = Receiver(
        directory,
        nick,
        port=args.port,
        max_size=args.max_size,
    )
    beacon = Beacon(nick, receiver.port, secrets.token_hex(4), allow=_allow_who(directory, "Everyone"))
    beacon.start()
    print(f"Listening on {_local_ip()}:{receiver.port} (also 127.0.0.1:{receiver.port}).")
    print(f"Nickname {nick}. Others on this network can find you, or use --to.")
    print("Path: Wi-Fi LAN (TCP, encrypted)")
    try:
        receiver.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        beacon.stop()
        receiver.stop()
    return 0


def _cmd_send(args: argparse.Namespace) -> int:
    if args.web:
        if len(args.paths) != 1:
            print("Use one file with --web.")
            return 2
        target = Path(args.paths[0])
        if not target.is_file():
            print(f"Could not read {target}.")
            return 2
        drop = WebDrop(target, host="0.0.0.0", advertise=_local_ip())
        drop.start()
        qr_path = Path("web-qr.png")
        write_qr(drop.url(), qr_path)
        print(drop.url())
        print(f"Verification code: {drop.code}")
        print(f"QR written to {qr_path.resolve()}")
        print("Release the file? [y/N]")
        try:
            answer = sys.stdin.readline()
        except Exception:
            answer = ""
        if answer.strip().lower() not in {"y", "yes"}:
            print("Receiver declined.")
            drop.stop()
            return 1
        drop.approve()
        print("Released. Waiting up to 5 minutes for the download.")
        deadline = __import__("time").monotonic() + drop.ttl
        while __import__("time").monotonic() < deadline and not drop.used:
            __import__("time").sleep(0.2)
        drop.stop()
        print("Sent." if drop.used else "The download was not taken.")
        return 0 if drop.used else 1
    if args.text:
        if not args.to:
            print("Use --to HOST:PORT with a text note.")
            return 2
        host, port = parse_hostport(args.to)
        return send_text(host, port, _nick(args.nick), args.text)
    if not args.paths:
        print("Name a file to send.")
        return 2
    paths = [Path(item) for item in args.paths]
    for path in paths:
        if path.is_dir():
            continue
        if not path.is_file():
            print(f"Could not read {path}.")
            return 2
    if args.to:
        host, port = parse_hostport(args.to)
    else:
        peers = discover(window=args.window)
        if args.peer:
            peers = [peer for peer in peers if peer.nick == args.peer]
        if not peers:
            print("Couldn't search the network. Use --to HOST:PORT to connect directly.")
            return 2
        if len(peers) > 1 and not args.peer:
            for index, peer in enumerate(peers, start=1):
                print(f"{index}. {peer.nick} ({peer.ip}:{peer.port})")
            print("Use --peer NICK or --to HOST:PORT.")
            return 2
        chosen = peers[0]
        print(f"Send to {chosen.nick} ({chosen.ip})? [y/N]")
        answer = sys.stdin.readline()
        if answer.strip().lower() not in {"y", "yes"}:
            print("Receiver declined.")
            return 1
        host, port = chosen.ip, chosen.port
    cancel = threading.Event()

    def _stop(_sig=None, _frame=None) -> None:
        cancel.set()

    try:
        import signal

        signal.signal(signal.SIGINT, _stop)
    except Exception:
        pass
    directory = Path(args.dir)
    private = load_identity(identity_path(directory))
    rotating = ""
    if args.contact:
        row = Contacts(directory / ".netdrive" / "contacts.json").by_nick(args.contact)
        if row and row.get("secret"):
            rotating = rotating_id(bytes.fromhex(row["secret"])).hex()
    return send_files(
        paths,
        host,
        port,
        _nick(args.nick),
        cancel=cancel,
        static_private=private,
        sender_pk=public_raw(private).hex(),
        rotating=rotating,
    )


def _cmd_discover(args: argparse.Namespace) -> int:
    peers = discover(window=args.window)
    if not peers:
        print("Couldn't search the network. Use --to HOST:PORT to connect directly.")
        return 0
    for peer in peers:
        print(f"{peer.nick}  {peer.ip}:{peer.port}")
    return 0


def _cmd_identity(args: argparse.Namespace) -> int:
    path = identity_path(Path(args.dir))
    if args.identity_cmd == "rotate-now":
        secret = load_contact_secret(Path(args.dir))
        first = rotating_id(secret)
        second = rotating_id(secret, forced_distinct_prefix(first[:8]))
        print(first.hex())
        print(second.hex())
        print("16 minutes apart. The two samples share no byte in the same position.")
        return 0
    if args.identity_cmd != "reset":
        print("Use: netdrive identity reset, or netdrive identity rotate-now")
        return 2
    print("This replaces the key. Type RESET to continue.")
    typed = sys.stdin.readline().strip()
    if typed != "RESET":
        print("The key was left as it is.")
        return 1
    private = reset_identity(path)
    print("New public key " + public_raw(private).hex())
    return 0


def _cmd_contact(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    private = load_identity(identity_path(directory))
    if args.contact_cmd == "show":
        uri = contact_uri(public_raw(private).hex(), load_contact_secret(directory).hex())
        image = directory / "contact-qr.png"
        image.parent.mkdir(parents=True, exist_ok=True)
        write_qr(uri, image)
        print(uri)
        print(f"QR written to {image.resolve()}")
        return 0
    if args.contact_cmd == "import":
        pk, secret = parse_contact_uri(args.link)
        book = Contacts(directory / ".netdrive" / "contacts.json")
        book.add(args.nick, pk, secret, auto=False)
        print(f"Saved contact {args.nick}.")
        return 0
    print("Use: netdrive contact show, or netdrive contact import LINK --nick NAME")
    return 2


def build_parser() -> argparse.ArgumentParser:
    """The argument parser. There is no flag that skips the accept prompt."""
    parser = argparse.ArgumentParser(prog="netdrive", description="Send a file to a nearby computer.")
    parser.add_argument("--version", action="version", version=f"netdrive {__version__}")
    commands = parser.add_subparsers(dest="command")

    receive = commands.add_parser("receive", help="Wait for files.")
    receive.add_argument("--dir", default="netdrive-received")
    receive.add_argument("--nick", default=None)
    receive.add_argument("--port", type=int, default=0)
    receive.add_argument("--max-size", type=int, default=4 * 1024**3)
    receive.set_defaults(func=_cmd_receive)

    send = commands.add_parser("send", help="Send files or one folder.")
    send.add_argument("paths", nargs="*")
    send.add_argument("--to", default=None)
    send.add_argument("--peer", default=None)
    send.add_argument("--nick", default=None)
    send.add_argument("--window", type=float, default=3.0)
    send.add_argument("--text", default=None)
    send.add_argument("--web", action="store_true")
    send.add_argument("--dir", default="netdrive-received")
    send.add_argument("--contact", default=None)
    send.set_defaults(func=_cmd_send)

    discover_cmd = commands.add_parser("discover", help="List nearby receivers.")
    discover_cmd.add_argument("--window", type=float, default=3.0)
    discover_cmd.set_defaults(func=_cmd_discover)

    identity = commands.add_parser("identity", help="Manage the local key.")
    identity.add_argument("--dir", default="netdrive-received")
    identity_sub = identity.add_subparsers(dest="identity_cmd")
    identity_sub.add_parser("reset")
    identity_sub.add_parser("rotate-now")
    identity.set_defaults(func=_cmd_identity)

    contact = commands.add_parser("contact", help="Show or import a contact QR link.")
    contact_sub = contact.add_subparsers(dest="contact_cmd")
    shown = contact_sub.add_parser("show")
    shown.add_argument("--dir", default="netdrive-received")
    imported = contact_sub.add_parser("import")
    imported.add_argument("link")
    imported.add_argument("--nick", required=True)
    imported.add_argument("--dir", default="netdrive-received")
    contact.set_defaults(func=_cmd_contact)

    ui = commands.add_parser("ui", help="Open the local window in a browser.")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--dir", default="netdrive-received")
    ui.set_defaults(func=_cmd_ui)

    commands.add_parser("demo_mitm", help="Show the verification code under a proxy.").set_defaults(
        func=lambda _args: (print(run_demo()) or 0)
    )
    sim = commands.add_parser("sim", help="Run a simulated radio or mesh check.")
    sim.add_argument("which", choices=("mesh", "path"))
    sim.set_defaults(func=_cmd_sim)
    return parser


def _cmd_ui(args: argparse.Namespace) -> int:
    from netdrive.ui.server import serve

    serve(Path(args.dir), args.port)
    return 0


def _cmd_sim(args: argparse.Namespace) -> int:
    if args.which == "mesh":
        print(run_mesh())
    else:
        print(path_report(sleeper=__import__("time").sleep))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run one command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    try:
        return int(func(args) or 0)
    except ValueError as exc:
        print(str(exc))
        return 2
    except KeyboardInterrupt:
        print("\nCancelled. Partial files removed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
