"""Entrypoints: dmarc-service web | smtp | migrate"""

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="dmarc-service")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("web", help="run the API/UI web server")
    sub.add_parser("smtp", help="run the SMTP report receiver")
    sub.add_parser("migrate", help="create/upgrade the database schema")
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
    elif args.command == "migrate":
        from dmarc_service.db.migrate import upgrade

        upgrade()
    else:  # pragma: no cover
        sys.exit(2)


if __name__ == "__main__":
    main()
