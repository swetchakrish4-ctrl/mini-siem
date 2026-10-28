"""Admin CLI.   python -m app.cli create-agent NAME | create-user NAME ROLE | list-agents | verify-chain"""
import argparse

from sqlalchemy import select

from .db import SessionLocal, init_db
from .crypto import hash_password
from .models import Agent, User
from .pipeline import verify_chain
from .security import generate_api_key, hash_key


def main() -> None:
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-agent", help="register a host and print its API key (shown once)")
    c.add_argument("hostname")
    u = sub.add_parser("create-user", help="create a dashboard user (role: admin | analyst | viewer)")
    u.add_argument("username")
    u.add_argument("role", choices=["admin", "analyst", "viewer"])
    u.add_argument("--password", help="omit to be prompted")
    sub.add_parser("list-agents")
    sub.add_parser("verify-chain", help="check the log hash chain for tampering")
    args = p.parse_args()

    init_db()
    with SessionLocal() as db:
        if args.cmd == "create-agent":
            if db.execute(select(Agent).where(Agent.hostname == args.hostname)).scalar_one_or_none():
                raise SystemExit(f"agent '{args.hostname}' already exists")
            key = generate_api_key()
            db.add(Agent(hostname=args.hostname, api_key_hash=hash_key(key)))
            db.commit()
            print(f"Agent '{args.hostname}' created.\nAPI key (save it now, it is not stored): {key}")
        elif args.cmd == "create-user":
            import getpass
            pw = args.password or getpass.getpass("password (min 8 chars): ")
            if len(pw) < 8:
                raise SystemExit("password must be at least 8 characters")
            if db.execute(select(User).where(User.username == args.username)).scalar_one_or_none():
                raise SystemExit("user already exists")
            db.add(User(username=args.username, password_hash=hash_password(pw), role=args.role))
            db.commit()
            print(f"user '{args.username}' ({args.role}) created")
        elif args.cmd == "list-agents":
            for a in db.execute(select(Agent).order_by(Agent.hostname)).scalars():
                print(f"{a.hostname:25} last_seen={a.last_seen}")
        else:
            print(verify_chain(db))


if __name__ == "__main__":
    main()
