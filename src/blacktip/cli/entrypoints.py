import argparse
from signal import signal, SIGINT

from blacktip import __title__ as NAME
from blacktip import __version__ as VERSION
from blacktip import __logger_default_level__ as LOGGER_DEFAULT_LEVEL
from blacktip import __save_data_interval__default__ as SAVE_DATA_INTERVAL_DEFAULT
from blacktip import __nmap__exec__ as NMAP_EXEC
from blacktip.utils.utils import out

from blacktip.exceptions import BlacktipException


def sigint_handler(__signal_received, __frame):
    print("SIGINT received, exiting.")
    exit(0)


def blacktip():
    signal(SIGINT, sigint_handler)
    from blacktip.blacktip import Blacktip  # late import to speed up situations where blacktip() is not started

    parser = argparse.ArgumentParser(
        epilog="{} v{}".format(NAME, VERSION),
        add_help=True,
        description="""
            Passive network security scanner for real-time ARP traffic analysis, device fingerprinting, and threat
            detection on Linux systems. Monitors ARP packets to discover devices, track network changes, and detect
            potential security threats with zero active network traffic generation.
        """,
    )

    # parser_group0
    # ===
    parser_group0 = parser.add_argument_group(title="datafile arguments")
    parser_group0.add_argument(
        "-f",
        "--datafile",
        required=False,
        type=str,
        metavar="<datafile>",
        help="The blacktip datafile where ARP event data is stored (SQLite database).",
    )
    parser_group0.add_argument(
        "-i",
        "--interval",
        required=False,
        default=SAVE_DATA_INTERVAL_DEFAULT,
        type=int,
        metavar="<seconds>",
        help="Interval seconds between writing to the datafile (DEFAULT: {})".format(SAVE_DATA_INTERVAL_DEFAULT),
    )
    parser_group0.add_argument(
        "--interface",
        required=False,
        type=str,
        metavar="<interface>",
        help="Network interface to monitor (e.g., eth0, wlan0). If not specified, scapy will choose default.",
    )

    # parser_group1 - request
    # ===
    parser_group1 = parser.add_mutually_exclusive_group()
    parser_group1.add_argument(
        "-req",
        "--new-request",
        required=False,
        default=False,
        action="store_true",
        help="Report ARP request packets with new IP/MAC addresses not yet observed (default behavior if no request flags specified).",
    )

    parser_group1.add_argument(
        "-noreq",
        "--no-request",
        required=False,
        default=False,
        action="store_true",
        help="Ignore all ARP request packet events.",
    )

    parser_group1.add_argument(
        "-allreq",
        "--all-request",
        required=False,
        default=False,
        action="store_true",
        help="Report all ARP request packets regardless of whether addresses have been previously observed.",
    )

    # parser_group2 - reply
    # ===
    parser_group2 = parser.add_mutually_exclusive_group()
    parser_group2.add_argument(
        "-rep",
        "--new-reply",
        required=False,
        default=False,
        action="store_true",
        help="Report ARP reply packets with new IP/MAC addresses not yet observed (default behavior if no reply flags specified).",
    )

    parser_group2.add_argument(
        "-norep",
        "--no-reply",
        required=False,
        default=False,
        action="store_true",
        help="Ignore all ARP reply packet events.",
    )

    parser_group2.add_argument(
        "-allrep",
        "--all-reply",
        required=False,
        default=False,
        action="store_true",
        help="Report all ARP reply packets regardless of whether addresses have been previously observed.",
    )

    # parser_group3
    # ===
    parser_group3 = parser.add_argument_group(
        title="ARP event command execution arguments",
        description="The following exec command substitutions are available: "
        "{IP}=ipv4-address, "
        "{HW}=hardware-address, "
        "{TS}=timestamp-utc, "
        "{ts}=timestamp-utc-short",
    )
    parser_group3.add_argument(
        "-e",
        "--exec",
        required=False,
        type=str,
        metavar="<command>",
        help="Command line to exec on selected ARP events. Commands are run asynchronously. "
        "If specified, this disables automatic nmap scanning.",
    )
    parser_group3.add_argument(
        "-n",
        "--nmap",
        required=False,
        default=True,
        action="store_true",
        dest="nmap",
        help="Run nmap against new IPv4 targets with results saved to database (enabled by DEFAULT). "
        "Use --no-nmap to disable.",
    )
    parser_group3.add_argument(
        "--no-nmap",
        required=False,
        action="store_false",
        dest="nmap",
        help="Disable automatic nmap scanning.",
    )
    parser_group3.add_argument(
        "-u",
        "--user",
        required=False,
        type=str,
        metavar="<user>",
        help="User to exec commands with, if not set this will be the same user context as blacktip.",
    )

    # parser_group4
    # ===
    parser_group4 = parser.add_argument_group(
        title="run-mode arguments", description="Switches that invoke run-modes other than ARP capture."
    )
    parser_group4.add_argument(
        "-q",
        "--query",
        required=False,
        type=str,
        metavar="<address>",
        help="Query the <datafile> for an IPv4 or HW address and return results in JSON formatted output and exit.",
    )
    parser_group4.add_argument(
        "-v",
        "--version",
        required=False,
        default=False,
        action="store_true",
        help="Return the blacktip version and exit.",
    )
    parser_group4.add_argument(
        "-d", "--debug", required=False, default=False, action="store_true", help="Debug messages to stdout."
    )
    parser_group4.add_argument(
        "--metrics",
        required=False,
        default=True,
        action="store_true",
        dest="metrics",
        help="Enable metrics collection and periodic logging (DEFAULT). Use --no-metrics to disable.",
    )
    parser_group4.add_argument(
        "--no-metrics",
        required=False,
        action="store_false",
        dest="metrics",
        help="Disable metrics collection.",
    )
    parser_group4.add_argument(
        "--metrics-interval",
        required=False,
        default=300,
        type=int,
        metavar="<seconds>",
        help="Interval in seconds between metrics log output (DEFAULT: 300).",
    )

    args = parser.parse_args()

    # Determine which command to execute
    # Priority: --exec (user specified) > --nmap (default)
    exec_command = getattr(args, "exec")
    if exec_command:
        exe = exec_command  # User provided explicit command, takes precedence
    elif args.nmap:
        exe = NMAP_EXEC  # Default nmap execution
    else:
        exe = None  # No execution

    if args.no_request:
        request_select = "nil"
    elif args.all_request:
        request_select = "all"
    else:
        request_select = "new"

    if args.no_reply:
        reply_select = "nil"
    elif args.all_reply:
        reply_select = "all"
    else:
        reply_select = "new"

    if args.debug:
        logger_level = "debug"
    else:
        logger_level = LOGGER_DEFAULT_LEVEL

    try:
        blacktip = Blacktip(logger_level=logger_level)
        if args.version:
            out(blacktip.do_version())
        elif args.query and args.datafile:
            out(blacktip.do_query(datafile=args.datafile, query=args.query))
        elif args.datafile:
            try:
                blacktip.do_sniffer(
                    datafile=args.datafile,
                    save_interval=args.interval,
                    request_select=request_select,
                    reply_select=reply_select,
                    exe=exe,
                    exec_user=args.user,
                    interface=args.interface,
                    enable_metrics=args.metrics,
                    metrics_interval=args.metrics_interval,
                )
            except KeyboardInterrupt:
                pass
        else:
            parser.print_help()

    except BlacktipException as e:
        print("")
        print("{} v{}".format(NAME, VERSION))
        print("ERROR: ", end="")
        for err in iter(e.args):
            print(err)
        print("")
        exit(9)
