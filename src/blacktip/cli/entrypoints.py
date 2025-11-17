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


def blacktip_state_monitor():
    """Run the device state monitor"""
    signal(SIGINT, sigint_handler)
    from blacktip.utils.database import BlacktipDatabase
    from blacktip.utils.state_monitor import DeviceStateMonitor
    from blacktip.utils import logger
    
    parser = argparse.ArgumentParser(
        epilog="{} State Monitor v{}".format(NAME, VERSION),
        add_help=True,
        description="Monitor device online/offline state transitions and log events to database.",
    )
    
    parser.add_argument(
        "-f",
        "--datafile",
        required=True,
        type=str,
        metavar="<datafile>",
        help="The blacktip datafile (SQLite database).",
    )
    
    parser.add_argument(
        "-i",
        "--interval",
        required=False,
        default=60,
        type=int,
        metavar="<seconds>",
        help="Interval in seconds between state checks (DEFAULT: 60).",
    )
    
    parser.add_argument(
        "--interface",
        required=False,
        type=str,
        metavar="<interface>",
        help="Network interface for active probing (e.g., eth0, wlan0).",
    )
    
    parser.add_argument(
        "-t",
        "--offline-threshold",
        required=False,
        default=300,
        type=int,
        metavar="<seconds>",
        help="Mark device offline after N seconds of inactivity (DEFAULT: 300 = 5 minutes).",
    )
    
    # Active probing arguments
    parser.add_argument(
        "--enable-probing",
        required=False,
        default=True,
        action="store_true",
        dest="enable_probing",
        help="Enable active ARP/ICMP probing (DEFAULT).",
    )
    
    parser.add_argument(
        "--no-probing",
        required=False,
        action="store_false",
        dest="enable_probing",
        help="Disable active probing - use passive monitoring only.",
    )
    
    parser.add_argument(
        "--probe-timeout",
        required=False,
        default=1.0,
        type=float,
        metavar="<seconds>",
        help="Timeout in seconds per probe attempt (DEFAULT: 1.0).",
    )
    
    parser.add_argument(
        "--probe-retries",
        required=False,
        default=2,
        type=int,
        metavar="<count>",
        help="Number of retries for failed probes (DEFAULT: 2).",
    )
    
    parser.add_argument(
        "--probe-failure-threshold",
        required=False,
        default=2,
        type=int,
        metavar="<count>",
        help="Consecutive probe failures before marking offline (DEFAULT: 2).",
    )
    
    parser.add_argument(
        "--no-icmp-fallback",
        required=False,
        default=True,
        action="store_false",
        dest="icmp_fallback",
        help="Disable ICMP ping fallback when ARP probe fails (DEFAULT: enabled).",
    )
    
    parser.add_argument(
        "--no-probe-before-offline",
        required=False,
        default=True,
        action="store_false",
        dest="probe_before_offline",
        help="Disable probing device before marking offline (DEFAULT: enabled).",
    )
    
    parser.add_argument(
        "--periodic-probe-interval",
        required=False,
        default=5,
        type=int,
        metavar="<cycles>",
        help="Probe all online devices every N cycles to keep fresh (0=disabled, DEFAULT: 5).",
    )
    
    parser.add_argument(
        "-d", 
        "--debug", 
        required=False, 
        default=False, 
        action="store_true", 
        help="Debug messages to stdout."
    )
    
    args = parser.parse_args()
    
    logger_level = "debug" if args.debug else LOGGER_DEFAULT_LEVEL
    logger.init(name=NAME, level=logger_level)
    
    try:
        db = BlacktipDatabase(args.datafile)
        monitor = DeviceStateMonitor(
            db,
            offline_threshold_seconds=args.offline_threshold,
            enable_active_probing=args.enable_probing,
            probe_timeout=args.probe_timeout,
            probe_retry_count=args.probe_retries,
            probe_failure_threshold=args.probe_failure_threshold,
            enable_icmp_fallback=args.icmp_fallback,
            probe_before_offline=args.probe_before_offline,
            periodic_probe_interval=args.periodic_probe_interval,
            interface=args.interface
        )
        monitor.run_forever(check_interval_seconds=args.interval)
    except KeyboardInterrupt:
        print("\nState monitor stopped")
    except Exception as e:
        print("Error: {}".format(e))
        exit(1)


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

    # parser_group5 - Speed test scheduler
    # ===
    parser_group5 = parser.add_argument_group(
        title="speed test scheduler arguments",
        description="Enable automatic internet speed testing at regular intervals."
    )
    parser_group5.add_argument(
        "--enable-speedtest",
        required=False,
        default=False,
        action="store_true",
        dest="enable_speedtest",
        help="Enable automatic speed test scheduling (requires APScheduler and speedtest-cli).",
    )
    parser_group5.add_argument(
        "--speedtest-interval",
        required=False,
        default=1,
        type=int,
        metavar="<hours>",
        help="Interval in hours between automatic speed tests (DEFAULT: 1).",
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
                    enable_speedtest=args.enable_speedtest,
                    speedtest_interval_hours=args.speedtest_interval,
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
