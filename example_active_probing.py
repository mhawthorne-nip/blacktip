#!/usr/bin/env python3
"""
Example: Running blacktip state monitor with active probing

This example demonstrates how to run the blacktip state monitor with
various active probing configurations.
"""

import subprocess
import sys


def run_state_monitor(args):
    """Run the state monitor with provided arguments"""
    cmd = ["blacktip-state-monitor"] + args
    print(f"Running: {' '.join(cmd)}")
    print("-" * 80)
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nStopped by user")


def example_default():
    """Example 1: Default configuration with active probing enabled"""
    print("\n" + "="*80)
    print("EXAMPLE 1: Default Configuration (Active Probing Enabled)")
    print("="*80)
    print("""
    - Offline threshold: 5 minutes (300 seconds)
    - Active probing: Enabled
    - Probe before offline: Yes
    - Periodic probing: Every 5 cycles
    - ICMP fallback: Enabled
    """)
    
    run_state_monitor([
        "-f", "blacktip.db",
        "-i", "60",
    ])


def example_conservative():
    """Example 2: Conservative detection (fewer false positives)"""
    print("\n" + "="*80)
    print("EXAMPLE 2: Conservative Detection")
    print("="*80)
    print("""
    - Offline threshold: 10 minutes (600 seconds)
    - Probe failure threshold: 3 (requires 3 failures)
    - Probe retries: 3
    - Less likely to mark devices offline incorrectly
    """)
    
    run_state_monitor([
        "-f", "blacktip.db",
        "--offline-threshold", "600",
        "--probe-failure-threshold", "3",
        "--probe-retries", "3",
    ])


def example_aggressive():
    """Example 3: Aggressive detection (faster offline detection)"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Aggressive Detection")
    print("="*80)
    print("""
    - Offline threshold: 2 minutes (120 seconds)
    - Probe failure threshold: 1 (single failure marks offline)
    - Probe retries: 1
    - Faster detection of truly offline devices
    """)
    
    run_state_monitor([
        "-f", "blacktip.db",
        "--offline-threshold", "120",
        "--probe-failure-threshold", "1",
        "--probe-retries", "1",
    ])


def example_passive_only():
    """Example 4: Passive monitoring only (no active probing)"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Passive Monitoring Only")
    print("="*80)
    print("""
    - Active probing: Disabled
    - Offline threshold: 5 minutes (300 seconds)
    - Uses only passive ARP traffic monitoring
    - Original behavior with configurable timeout
    """)
    
    run_state_monitor([
        "-f", "blacktip.db",
        "--no-probing",
        "--offline-threshold", "300",
    ])


def example_frequent_probing():
    """Example 5: Frequent periodic probing"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Frequent Periodic Probing")
    print("="*80)
    print("""
    - Periodic probe interval: Every 2 cycles
    - Probes all online devices every 2 minutes
    - Keeps device timestamps very fresh
    - Higher network overhead but more accurate
    """)
    
    run_state_monitor([
        "-f", "blacktip.db",
        "--periodic-probe-interval", "2",
    ])


def example_large_network():
    """Example 6: Configuration for large networks"""
    print("\n" + "="*80)
    print("EXAMPLE 6: Large Network Configuration")
    print("="*80)
    print("""
    - Periodic probing: Disabled (0)
    - Probe only before offline transitions
    - Reduces overhead for networks with many devices
    - Still prevents false offline transitions
    """)
    
    run_state_monitor([
        "-f", "blacktip.db",
        "--periodic-probe-interval", "0",
        "--probe-before-offline",
    ])


def show_help():
    """Show all available options"""
    print("\n" + "="*80)
    print("BLACKTIP STATE MONITOR - HELP")
    print("="*80)
    subprocess.run(["blacktip-state-monitor", "--help"])


def main():
    """Main function to run examples"""
    examples = {
        "1": ("Default Configuration", example_default),
        "2": ("Conservative Detection", example_conservative),
        "3": ("Aggressive Detection", example_aggressive),
        "4": ("Passive Only", example_passive_only),
        "5": ("Frequent Probing", example_frequent_probing),
        "6": ("Large Network", example_large_network),
        "h": ("Show Help", show_help),
    }
    
    print("\n" + "="*80)
    print("BLACKTIP STATE MONITOR - ACTIVE PROBING EXAMPLES")
    print("="*80)
    print("\nAvailable examples:")
    for key, (name, _) in examples.items():
        print(f"  {key}. {name}")
    print()
    
    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        choice = input("Select an example (or 'h' for help): ").strip()
    
    if choice in examples:
        _, func = examples[choice]
        func()
    else:
        print(f"Invalid choice: {choice}")
        print("Use: python example_active_probing.py [1-6|h]")
        sys.exit(1)


if __name__ == "__main__":
    main()
