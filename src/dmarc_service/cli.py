"""Entrypoints: dmarc-service web | smtp | migrate"""

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="dmarc-service")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("web", help="run the API/UI web server")
    sub.add_parser("smtp", help="run the SMTP report receiver")
    imap = sub.add_parser("imap", help="fetch reports from an IMAP mailbox")
    imap.add_argument("--once", action="store_true", help="fetch and exit")
    sub.add_parser("migrate", help="create/upgrade the database schema")
    sub.add_parser("enrich", help="resolve owners for source IPs seen in reports")
    sub.add_parser("backup", help="dump the database to S3-compatible storage")
    sub.add_parser("reprocess", help="re-run stored messages that produced no report")

    # Break-glass: run these on the server when nobody can sign in, for
    # example after an SSO misconfiguration locked out the only admin.
    set_password = sub.add_parser(
        "set-password", help="set a user's password (creates the user if needed)"
    )
    set_password.add_argument("email")
    set_password.add_argument("--password", help="read from stdin prompt when omitted")
    set_password.add_argument("--admin", action="store_true", help="also make them an admin")

    disable_sso = sub.add_parser("disable-sso", help="remove the SSO provider configuration")
    disable_sso.add_argument("--yes", action="store_true", required=True)
    args = parser.parse_args(argv)

    if args.command == "web":
        import uvicorn

        from dmarc_service.config import get_settings

        settings = get_settings()
        uvicorn.run(
            "dmarc_service.api.app:app", host=settings.web_host, port=settings.web_port
        )
    elif args.command == "smtp":
        from dmarc_service.smtp.server import run

        run()
    elif args.command == "imap":
        from dmarc_service.ingest.imap import fetch_once, run

        if args.once:
            print(fetch_once())
        else:
            run()
    elif args.command == "migrate":
        from dmarc_service.db.migrate import upgrade
        from dmarc_service.db.session import session_scope
        from dmarc_service.ingest.pipeline import reprocess

        upgrade()
        # Every release may teach the parser a new format or fix routing, so
        # replay whatever could not be stored before. Messages are kept
        # verbatim precisely because senders never resend them.
        with session_scope() as db:
            counts = reprocess(db)
        if counts["recovered"]:
            print(f"recovered {counts['recovered']} previously unstored message(s)")
    elif args.command == "enrich":
        from dmarc_service.db.session import session_scope
        from dmarc_service.ingest.enrich import backfill

        with session_scope() as db:
            print(f"resolved {backfill(db)} IP(s)")
    elif args.command == "backup":
        import logging

        from dmarc_service.backup import run

        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
        print(f"backed up to {run()}")
    elif args.command == "reprocess":
        from dmarc_service.db.session import session_scope
        from dmarc_service.ingest.pipeline import reprocess

        with session_scope() as db:
            print(reprocess(db))
    elif args.command == "set-password":
        import getpass

        from sqlalchemy import select

        from dmarc_service.auth import service as auth
        from dmarc_service.db.models import User
        from dmarc_service.db.session import session_scope

        password = args.password or getpass.getpass("New password: ")
        if len(password) < 8:
            sys.exit("password must be at least 8 characters")
        with session_scope() as db:
            user = db.scalar(select(User).where(User.email == args.email.lower()))
            if user is None:
                user = auth.create_user(db, args.email, password, is_admin=args.admin)
                print(f"created {user.email}")
            else:
                auth.set_password(db, user, password)
                if args.admin:
                    user.is_admin = True
                print(f"password updated for {user.email}")
    elif args.command == "disable-sso":
        from dmarc_service.auth import service as auth
        from dmarc_service.db.session import session_scope

        with session_scope() as db:
            auth.remove_provider(db)
        print("SSO configuration removed; password sign-in still works")
    else:  # pragma: no cover
        sys.exit(2)


if __name__ == "__main__":
    main()
