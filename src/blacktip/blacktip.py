import time
from datetime import datetime, timedelta

from blacktip import __title__ as NAME
from blacktip import __version__ as VERSION
from blacktip import __save_data_interval__default__ as SAVE_DATA_INTERVAL_DEFAULT
from blacktip import __nmap_refresh_interval__ as NMAP_REFRESH_INTERVAL
from blacktip import __nmap_refresh_threshold_days__ as NMAP_REFRESH_THRESHOLD_DAYS
from blacktip import __speedtest_scheduler_enabled__ as SPEEDTEST_SCHEDULER_ENABLED
from blacktip import __speedtest_interval_hours__ as SPEEDTEST_INTERVAL_HOURS
from blacktip.utils.utils import out
from blacktip.utils.utils import timestamp
from blacktip.utils import logger
from blacktip.utils.database import BlacktipDatabase
from blacktip.utils.sniffer import BlacktipSniffer
from blacktip.utils.exe import BlacktipExec
from blacktip.utils.metrics import get_metrics
from blacktip.exceptions import BlacktipException

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from blacktip.utils.speedtest_service import SpeedTestService
    SPEEDTEST_AVAILABLE = True
except ImportError:
    SPEEDTEST_AVAILABLE = False
    logger.warning("APScheduler or speedtest binary not available. Speed test scheduling disabled.")


class Blacktip:
    def __init__(self, logger_level="warning"):
        logger.init(name=NAME, level=logger_level)
        logger.debug("{} v{}".format(NAME, VERSION))

    def do_version(self):
        logger.debug("do_version()")
        return {"version": VERSION}

    def do_query(self, datafile, query):
        logger.debug("do_query()")

        db = BlacktipDatabase(datafile)
        return db.query_by_address(query)

    def do_sniffer(
        self,
        datafile,
        save_interval=SAVE_DATA_INTERVAL_DEFAULT,
        request_select="new",
        reply_select="new",
        exe=None,
        exec_user=None,
        interface=None,
        enable_metrics=False,
        metrics_interval=300,
        enable_speedtest=False,
        speedtest_interval_hours=None,
    ):

        logger.debug(
            "do_sniffer(datafile={}, save_interval={}, request_select={}, reply_select={}, exec={}, "
            "exec_user={}, interface={}, enable_metrics={}, metrics_interval={}, enable_speedtest={}, "
            "speedtest_interval_hours={})".format(
                datafile, save_interval, request_select, reply_select, exe, exec_user, interface,
                enable_metrics, metrics_interval, enable_speedtest, speedtest_interval_hours
            )
        )

        db = BlacktipDatabase(datafile)
        db.increment_starts()
        session_save_time = time.time()
        last_stats = db.get_statistics()
        session_data_count = last_stats["unique_ip_addresses"] + last_stats["unique_mac_addresses"]

        # Metrics tracking
        metrics = get_metrics() if enable_metrics else None
        last_metrics_log = time.time()

        # Nmap refresh tracking
        last_nmap_refresh_check = time.time()

        # Speed test scheduler setup
        scheduler = None
        speedtest_service = None
        
        if enable_speedtest and SPEEDTEST_AVAILABLE:
            logger.info("Speed test scheduler enabled")
            speedtest_service = SpeedTestService(database=db)
            scheduler = BackgroundScheduler()
            
            # Use provided interval or default
            interval_hours = speedtest_interval_hours or SPEEDTEST_INTERVAL_HOURS
            
            # Schedule automatic speed tests
            scheduler.add_job(
                func=lambda: speedtest_service.run_speed_test(triggered_by='scheduled'),
                trigger='interval',
                hours=interval_hours,
                id='speedtest_job',
                name='Automatic Speed Test',
                replace_existing=True
            )
            
            scheduler.start()
            logger.info("Speed test scheduled to run every {} hour(s)".format(interval_hours))
            
            # Run initial speed test after 60 seconds
            initial_run = datetime.now() + timedelta(seconds=60)
            scheduler.add_job(
                func=lambda: speedtest_service.run_speed_test(triggered_by='scheduled'),
                trigger='date',
                run_date=initial_run,
                id='speedtest_initial',
                name='Initial Speed Test'
            )
            logger.info("Initial speed test scheduled in 60 seconds")
            
        elif enable_speedtest and not SPEEDTEST_AVAILABLE:
            logger.warning("Speed test requested but dependencies not available. Install APScheduler and speedtest binary.")

        # Create a single sniffer instance for caching
        arp_sniffer = BlacktipSniffer()

        try:
            while True:
                batch_packets = []
                batch_start_time = time.time()

                try:
                    batch_packets = arp_sniffer.sniff_arp_packet_batch(interface=interface)
                    
                    if metrics:
                        batch_duration = time.time() - batch_start_time
                        metrics.record_time("sniff_batch_duration", batch_duration)
                        metrics.increment("packets_received", len(batch_packets))
                        
                except PermissionError:
                    logger.critical("{} requires root privileges to sniff network interfaces!".format(NAME))
                    exit(1)
                except KeyboardInterrupt:
                    logger.info("Received keyboard interrupt, exiting...")
                    if metrics:
                        metrics.log_stats()
                    raise
                except Exception as e:
                    logger.error("Error in packet sniffing: {}".format(e))
                    if metrics:
                        metrics.increment("sniff_errors")
                    time.sleep(1)  # Brief pause before retry
                    continue

                blacktipexec = BlacktipExec(db=db)
                packets_processed = 0
                triggers_fired = 0

                for packet in batch_packets:
                    try:
                        result = arp_sniffer.process_packet(packet, db)
                        if result is None:
                            if metrics:
                                metrics.increment("packets_invalid")
                            continue
                        
                        packet_data = result
                        packets_processed += 1

                        # Track packet types
                        if metrics:
                            metrics.increment("packets_{}".format(packet_data["op"]))
                            if packet_data.get("gratuitous"):
                                metrics.increment("packets_gratuitous")
                            if packet_data.get("anomalies"):
                                metrics.increment("anomalies_detected", len(packet_data["anomalies"]))

                        trigger = None
                        if packet_data["op"] == "request":
                            if request_select == "all":
                                trigger = "all_request"
                            elif request_select == "new" and packet_data["ip"]["new"] is True:
                                trigger = "new_ip_request"
                            elif request_select == "new" and packet_data["hw"]["new"] is True:
                                trigger = "new_hw_request"
                            else:
                                pass
                        elif packet_data["op"] == "reply":
                            if reply_select == "all":
                                trigger = "all_reply"
                            elif reply_select == "new" and packet_data["ip"]["new"] is True:
                                trigger = "new_ip_reply"
                            elif reply_select == "new" and packet_data["hw"]["new"] is True:
                                trigger = "new_hw_reply"
                            else:
                                pass
                        else:
                            raise BlacktipException("Unexpected packet_data[op]", packet_data["op"])

                        if trigger is not None:
                            triggers_fired += 1
                            output_data = {**packet_data, **{"trigger": trigger}}
                            # Remove None values for cleaner output
                            output_data = {k: v for k, v in output_data.items() if v is not None}
                            out(output_data, indent=0, flush=True)
                            blacktipexec.async_command_exec_thread(exe, packet_data, as_user=exec_user)
                            
                            if metrics:
                                metrics.increment("triggers_fired")
                                metrics.increment("trigger_{}".format(trigger))
                                
                    except Exception as e:
                        logger.error("Error processing packet: {}".format(e))
                        if metrics:
                            metrics.increment("packet_processing_errors")
                        continue

                if metrics:
                    metrics.set_gauge("packets_processed_last_batch", packets_processed)
                    metrics.set_gauge("triggers_fired_last_batch", triggers_fired)

                if len(blacktipexec.subprocess_list) > 0:
                    exec_start = time.time()
                    blacktipexec.async_command_exec_threads_wait()
                    if metrics:
                        metrics.record_time("exec_wait_duration", time.time() - exec_start)

                del blacktipexec

                # Update statistics periodically
                if time.time() > session_save_time + save_interval:
                    try:
                        stats = db.get_statistics()
                        current_data_count = stats["unique_ip_addresses"] + stats["unique_mac_addresses"]
                        
                        if current_data_count != session_data_count:
                            db.update_metadata("ts_last", timestamp())
                            session_data_count = current_data_count
                            logger.debug("Database updated: {} IPs, {} MACs".format(
                                stats["unique_ip_addresses"], stats["unique_mac_addresses"]))
                        
                        session_save_time = time.time()
                        
                        if metrics:
                            metrics.increment("database_updates")
                            metrics.set_gauge("unique_hw_addresses", stats["unique_mac_addresses"])
                            metrics.set_gauge("unique_ip_addresses", stats["unique_ip_addresses"])
                            
                    except Exception as e:
                        logger.error("Failed to update statistics: {}".format(e))
                        if metrics:
                            metrics.increment("database_update_errors")
                
                # Check for devices needing nmap refresh
                if exe and (time.time() - last_nmap_refresh_check) > NMAP_REFRESH_INTERVAL:
                    try:
                        devices_to_rescan = db.get_devices_needing_rescan(NMAP_REFRESH_THRESHOLD_DAYS)

                        if devices_to_rescan:
                            logger.info("Found {} device(s) with stale nmap data, triggering rescans".format(
                                len(devices_to_rescan)))

                            # Create executor for refresh scans
                            refresh_exec = BlacktipExec(db=db)

                            # Trigger nmap scans for each device
                            for device in devices_to_rescan:
                                packet_data = {
                                    "ip": {"addr": device['ip_address']},
                                    "hw": {"addr": device['mac_address']}
                                }

                                logger.debug("Scheduling refresh scan for {} (last scan: {})".format(
                                    device['ip_address'],
                                    device['last_scan_date'] or 'never'))

                                refresh_exec.async_command_exec_thread(exe, packet_data, as_user=exec_user)

                                if metrics:
                                    metrics.increment("nmap_refresh_scans_triggered")

                            # Wait for refresh scans to complete
                            if len(refresh_exec.subprocess_list) > 0:
                                logger.debug("Waiting for {} refresh scan(s) to complete".format(
                                    len(refresh_exec.subprocess_list)))
                                refresh_exec.async_command_exec_threads_wait()

                            del refresh_exec

                            if metrics:
                                metrics.increment("nmap_refresh_checks_with_scans")
                        else:
                            logger.debug("No devices need nmap refresh")
                            if metrics:
                                metrics.increment("nmap_refresh_checks_no_scans")

                        last_nmap_refresh_check = time.time()

                    except Exception as e:
                        logger.error("Failed to check/refresh stale nmap data: {}".format(e))
                        if metrics:
                            metrics.increment("nmap_refresh_errors")
                        last_nmap_refresh_check = time.time()  # Don't retry immediately

                # Log metrics periodically
                if metrics and enable_metrics and (time.time() - last_metrics_log) > metrics_interval:
                    metrics.log_stats()
                    last_metrics_log = time.time()
        
        finally:
            # Cleanup scheduler on exit
            if scheduler:
                logger.info("Shutting down speed test scheduler...")
                scheduler.shutdown(wait=False)
                logger.info("Speed test scheduler stopped")

