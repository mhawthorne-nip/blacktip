"""Metrics collection and reporting for blacktip"""
import time
from collections import defaultdict
from . import logger


class MetricsCollector:
    """Collect and track metrics for monitoring"""
    
    def __init__(self):
        self.start_time = time.time()
        self.counters = defaultdict(int)
        self.gauges = {}
        self.timers = defaultdict(list)
        
    def increment(self, metric_name, value=1):
        """Increment a counter metric"""
        self.counters[metric_name] += value
        
    def set_gauge(self, metric_name, value):
        """Set a gauge metric to a specific value"""
        self.gauges[metric_name] = value
        
    def record_time(self, metric_name, duration):
        """Record a timing measurement"""
        self.timers[metric_name].append(duration)
        # Keep only last 1000 measurements to prevent memory bloat
        if len(self.timers[metric_name]) > 1000:
            self.timers[metric_name] = self.timers[metric_name][-1000:]
    
    def get_stats(self):
        """Get current statistics"""
        uptime = time.time() - self.start_time
        
        stats = {
            "uptime_seconds": round(uptime, 2),
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "timers": {}
        }
        
        # Calculate timer statistics
        for name, measurements in self.timers.items():
            if measurements:
                stats["timers"][name] = {
                    "count": len(measurements),
                    "min": round(min(measurements), 4),
                    "max": round(max(measurements), 4),
                    "avg": round(sum(measurements) / len(measurements), 4),
                }
        
        return stats
    
    def log_stats(self):
        """Log current statistics"""
        stats = self.get_stats()
        logger.info("=== Metrics Report ===")
        logger.info("Uptime: {:.2f} seconds".format(stats["uptime_seconds"]))
        
        if stats["counters"]:
            logger.info("Counters:")
            for name, value in sorted(stats["counters"].items()):
                logger.info("  {}: {}".format(name, value))
        
        if stats["gauges"]:
            logger.info("Gauges:")
            for name, value in sorted(stats["gauges"].items()):
                logger.info("  {}: {}".format(name, value))
        
        if stats["timers"]:
            logger.info("Timers:")
            for name, timer_stats in sorted(stats["timers"].items()):
                logger.info("  {}: avg={:.4f}s min={:.4f}s max={:.4f}s count={}".format(
                    name, 
                    timer_stats["avg"],
                    timer_stats["min"],
                    timer_stats["max"],
                    timer_stats["count"]
                ))
    
    def reset(self):
        """Reset all metrics"""
        self.counters.clear()
        self.gauges.clear()
        self.timers.clear()
        self.start_time = time.time()


# Global metrics instance
_global_metrics = None


def get_metrics():
    """Get or create global metrics collector"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = MetricsCollector()
    return _global_metrics
