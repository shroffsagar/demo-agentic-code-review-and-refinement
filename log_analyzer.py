from typing import Tuple
"""
Log Analyzer - A utility for analyzing and extracting insights from log files.

This module provides functionality to parse, filter, and analyze log files
from various systems, identifying patterns and anomalies.
"""

import re
import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Tuple, Any
import os
import json


class LogEntry:
    """Represents a single log entry with parsed components."""

    def __init__(self, timestamp: datetime.datetime, level: str,
                 service: str, message: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a log entry.

        Args:
            timestamp: The timestamp of the log entry
            level: The log level (INFO, ERROR, etc.)
            service: The service or component that generated the log
            message: The log message content
            metadata: Additional metadata extracted from the log
        """
        self.timestamp = timestamp
        self.level = level
        self.service = service
        self.message = message
        self.metadata = metadata or {}

    def __str__(self) -> str:
        """Return a string representation of the log entry."""
        return f"[{self.timestamp}] {self.level} - {self.service}: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert the log entry to a dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "service": self.service,
            "message": self.message,
            "metadata": self.metadata
        }


class LogAnalyzer:
    """Parses and analyzes log files to extract insights."""

    # Common log level patterns
    LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

    # Common datetime formats in logs
    DATETIME_FORMATS = [
        "%Y-%m-%d %H:%M:%S,%f",  # 2023-04-15 14:32:15,123
        "%Y-%m-%d %H:%M:%S.%f",   # 2023-04-15 14:32:15.123
        "%Y-%m-%dT%H:%M:%S.%fZ",  # 2023-04-15T14:32:15.123Z
        "%d/%b/%Y:%H:%M:%S %z"    # 15/Apr/2023:14:32:15 +0000
    ]

    def __init__(self):
        """Initialize the log analyzer."""
        self.entries = []
        self.services = set()
        self.levels = set()

    def parse_file(self, file_path: str,
                   custom_pattern: Optional[str] = None) -> List[LogEntry]:
        """
        Parse a log file and extract structured log entries.

        Args:
            file_path: Path to the log file
            custom_pattern: Optional regex pattern to use for parsing

        Returns:
            List of extracted LogEntry objects

        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file can't be parsed properly
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Clear previous entries
        self.entries = []

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = self._parse_log_line(line, custom_pattern)
                    if entry:
                        self.entries.append(entry)
                        self.services.add(entry.service)
                        self.levels.add(entry.level)
                except Exception as e:
                    print(
                        f"Warning: Could not parse line: {line.strip()} - {e}")

        print(f"Parsed {len(self.entries)} log entries from {file_path}")
        return self.entries

    def parse_folder(self, folder_path: str,
                     file_pattern: str = "*.log") -> List[LogEntry]:
        """
        Parse all matching log files in a folder.

        Args:
            folder_path: Path to the folder containing log files
            file_pattern: Pattern to match log files (default: "*.log")

        Returns:
            List of all extracted LogEntry objects

        Raises:
            FileNotFoundError: If the folder doesn't exist
        """
        import glob

        if not os.path.exists(folder_path):
            raise FileNotFoundError(f"Folder not found: {folder_path}")

        # Clear previous entries
        self.entries = []

        # Get all matching files
        pattern = os.path.join(folder_path, file_pattern)
        files = glob.glob(pattern)

        for file_path in files:
            try:
                self.entries.extend(self.parse_file(file_path))
            except Exception as e:
                print(f"Error parsing {file_path}: {e}")

        return self.entries

    def _extract_json_metadata(self, message: str) -> Tuple[str, dict]:
    """
    Extract JSON metadata from the log message.

    Args:
        message: The log message string.

    Returns:
        A tuple of (message with JSON removed, metadata dict).
    """
    try:
        json_match = re.search(r'(\{.*?\})', message)
        if json_match:
            json_str = json_match.group(1)
            json_data = json.loads(json_str)
            if isinstance(json_data, dict):
                # Remove only the first occurrence of the JSON substring
                message = re.sub(r'(\{.*?\})', '', message, count=1).strip()
                return message, json_data
    except (json.JSONDecodeError, ValueError):
        pass
    return message, {}


def _parse_log_line(self, line: str,
                    custom_pattern: Optional[str] = None) -> Optional[LogEntry]:
    """
    Parse a single log line into a structured entry.

    Args:
        line: The log line text
        custom_pattern: Optional regex pattern to use

    Returns:
        LogEntry object or None if line couldn't be parsed
    """
    line = line.strip()
    if not line:
        return None

    if custom_pattern:
        # Use custom pattern if provided
        pattern = re.compile(custom_pattern)
        match = pattern.search(line)
        if match:
            # Extract fields based on named groups in the pattern
            fields = match.groupdict()

            # Parse timestamp
            timestamp_str = fields.get('timestamp', '')
            timestamp = self._parse_timestamp(timestamp_str)

            # Extract JSON metadata from message if present
            message = fields.get('message', line)
            message, extra_metadata = self._extract_json_metadata(message)

            metadata = {
                k: v for k,
                v in fields.items() if k not in (
                    'timestamp',
                    'level',
                    'service',
                    'message')}
            metadata.update(extra_metadata)

            return LogEntry(
                timestamp=timestamp or datetime.datetime.now(),
                level=fields.get('level', 'UNKNOWN'),
                service=fields.get('service', 'unknown'),
                message=message,
                metadata=metadata
            )
    else:
        # Default parsing logic - attempt to identify common log formats

        # Try to extract timestamp
        timestamp = None
        for format_str in self.DATETIME_FORMATS:
            match = re.search(r'\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2}', line)
            if match:
                timestamp_str = match.group(0)
                try:
                    timestamp = datetime.datetime.strptime(
                        timestamp_str, format_str.split('.')[0])
                    break
                except ValueError:
                    continue

        # Try to extract log level
        level = "INFO"  # Default level
        for lvl in self.LOG_LEVELS:
            if f" {lvl} " in line or f"[{lvl}]" in line:
                level = lvl
                break

        # Try to extract service name - assuming it's between brackets or
        # before a colon
        service = "unknown"
        bracket_match = re.search(r'\[([\w\-\.]+)\]', line)
        if bracket_match:
            service = bracket_match.group(1)
        else:
            # If not found in brackets, try to find it before a colon
            colon_match = re.search(r'\b([\w\-\.]+):', line)
            if colon_match:
                service = colon_match.group(1)

        # Message is everything after the timestamp and level
        message = line
        if timestamp:
            message = re.sub(
                r'^.*?' +
                re.escape(
                    str(timestamp)),
                '',
                message).strip()

        # Remove level and service from message
        message = re.sub(r'\b' + re.escape(level) + r'\b', '', message).strip()
        message = re.sub(
            r'\[' + re.escape(service) + r'\]',
            '',
            message).strip()
        message = message.lstrip(':').strip()

        # Extract and store any JSON data in the message using the helper
        # function
        message, metadata = self._extract_json_metadata(message)

        return LogEntry(
            timestamp=timestamp or datetime.datetime.now(),
            level=level,
            service=service,
            message=message,
            metadata=metadata
        )

    def _parse_timestamp(
            self, timestamp_str: str) -> Optional[datetime.datetime]:
        """
        Parse a timestamp string into a datetime object.

        Args:
            timestamp_str: String containing a timestamp

        Returns:
            Datetime object or None if parsing fails
        """
        if not timestamp_str:
            return None

        for format_str in self.DATETIME_FORMATS:
            try:
                return datetime.datetime.strptime(timestamp_str, format_str)
            except ValueError:
                continue

        return None

    def filter_by_level(self, levels: List[str]) -> List[LogEntry]:
        """
        Filter log entries by log level.

        Args:
            levels: List of log levels to include

        Returns:
            Filtered list of LogEntry objects
        """
        return [entry for entry in self.entries if entry.level in levels]

    def filter_by_service(self, services: List[str]) -> List[LogEntry]:
        """
        Filter log entries by service name.

        Args:
            services: List of service names to include

        Returns:
            Filtered list of LogEntry objects
        """
        return [entry for entry in self.entries if entry.service in services]

    def filter_by_timerange(self, start_time: datetime.datetime,
                            end_time: datetime.datetime) -> List[LogEntry]:
        """
        Filter log entries by a time range.

        Args:
            start_time: Start of the time range
            end_time: End of the time range

        Returns:
            Filtered list of LogEntry objects
        """
        return [entry for entry in self.entries
                if start_time <= entry.timestamp <= end_time]

    def search(self, query: str,
               case_sensitive: bool = False) -> List[LogEntry]:
        """
        Search for log entries containing the query string.

        Args:
            query: String to search for
            case_sensitive: Whether to perform case-sensitive search

        Returns:
            List of matching LogEntry objects
        """
        if not case_sensitive:
            query = query.lower()
            return [entry for entry in self.entries
                    if query in entry.message.lower()]
        else:
            return [entry for entry in self.entries
                    if query in entry.message]

    def get_error_summary(self) -> Dict[str, int]:
    """
    Get a summary of error counts by service.

    Returns:
        Dictionary mapping service names to error counts
    """
    error_counts = defaultdict(int)
    for entry in self.entries:
        if entry.level in ["ERROR", "CRITICAL"]:
            error_counts[entry.service.lower()] += 1
    return dict(error_counts)

    def get_activity_timeline(
            self, interval_minutes: int = 60) -> Dict[str, int]:
        """
        Generate an activity timeline showing log entry counts over time.

        Args:
            interval_minutes: Size of the time interval in minutes

        Returns:
            Dictionary mapping time intervals to log entry counts
        """
        if not self.entries:
            return {}

        # Sort entries by timestamp
        sorted_entries = sorted(self.entries, key=lambda x: x.timestamp)

        # Calculate time interval
        delta = datetime.timedelta(minutes=interval_minutes)

        # Define intervals
        start_time = sorted_entries[0].timestamp
        end_time = sorted_entries[-1].timestamp

        # Initialize timeline
        timeline = {}
        current = start_time

        while current <= end_time:
            interval_end = current + delta
            interval_key = current.strftime("%Y-%m-%d %H:%M")

            # Count entries in this interval
            count = sum(1 for entry in sorted_entries
                        if current <= entry.timestamp < interval_end)

            timeline[interval_key] = count
            current = interval_end

        return timeline

    def replace_placeholders(message: str) -> str:
    IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    UUID_PATTERN = re.compile(
        r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
    TIMESTAMP_PATTERN = re.compile(
        r'\b\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2}(?:\.\d+)?\b')
    URL_PATTERN = re.compile(r'https?://[\w\-\.]+(?:/[\w\-\./]*)?')
    NUMBER_PATTERN = re.compile(r'\b\d+\b')
    template = message
    template = IP_PATTERN.sub('<IP>', template)
    template = UUID_PATTERN.sub('<UUID>', template)
    template = TIMESTAMP_PATTERN.sub('<TIMESTAMP>', template)
    template = URL_PATTERN.sub('<URL>', template)
    template = NUMBER_PATTERN.sub('<NUMBER>', template)
    return template


def find_patterns(self, min_occurrences: int = 5) -> List[Tuple[str, int]]:
    """
    Find common patterns in log messages.

    Args:
        min_occurrences: Minimum number of occurrences to consider a pattern

    Returns:
        List of (pattern, count) tuples sorted by frequency
    """
    # Extract message templates by replacing specific values with
    # placeholders
    templates = []

    # Create a cache for processed messages to avoid duplicate processing
    processed_messages = {}

    for entry in self.entries:
        # Skip if we've already processed this exact message
        if entry.message in processed_messages:
            templates.append(processed_messages[entry.message])
            continue

        # Replace placeholders using helper function
        template = replace_placeholders(entry.message)

        # Store in cache
        processed_messages[entry.message] = template
        templates.append(template)

    # Count template occurrences
    counter = Counter(templates)

    # Filter by minimum occurrences and sort by frequency
    patterns = [(pattern, count)
                for pattern, count in counter.items() if count >= min_occurrences]

    return sorted(patterns, key=lambda x: x[1], reverse=True)

    def export_to_json(self, output_file: str) -> None:
        """
        Export parsed log entries to a JSON file.

        Args:
            output_file: Path to the output JSON file
        """
        if not self.entries:
            print("Warning: No entries to export")
            return

        # Convert entries to dictionaries
        data = [entry.to_dict() for entry in self.entries]

        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        print(f"Exported {len(data)} entries to {output_file}")

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive analysis report.

        Returns:
            Dictionary containing various analysis results
        """
        if not self.entries:
            return {"error": "No log entries to analyze"}

        # Get basic stats
        stats = {
            "total_entries": len(self.entries),
            "unique_services": list(self.services),
            "log_levels": {level: len(self.filter_by_level([level])) for level in self.levels},
            "time_range": {
                "start": min(entry.timestamp for entry in self.entries).isoformat(),
                "end": max(entry.timestamp for entry in self.entries).isoformat()
            }
        }

        # Get error summary
        error_summary = self.get_error_summary()

        # Get activity timeline
        timeline = self.get_activity_timeline()

        # Find common patterns
        patterns = self.find_patterns()

        # Combine results
        report = {
            "stats": stats,
            "error_summary": error_summary,
            "timeline": timeline,
            "patterns": patterns
        }

        return report

    def analyze_error_cascades(
            self, time_window: int = 60) -> List[Dict[str, Any]]:
    """
    Analyze error cascades across services within a specified time window.

    This method identifies chains of errors that occur across different services
    within a given time window, helping detect error propagation in distributed systems.

    Args:
        time_window: Time window in seconds to consider for related errors

    Returns:
        List of error cascade information, each containing:
        - start_time: When the cascade began
        - services: List of services involved in order
        - error_count: Total number of errors in the cascade
        - duration: Total duration of the cascade in seconds
    """
    if not self.entries:
        return []

    error_entries = sorted(
        [e for e in self.entries if e.level in ["ERROR", "CRITICAL"]],
        key=lambda x: x.timestamp
    )

    if not error_entries:
        return []

    cascades = []
    current_cascade = None

    for entry in error_entries:
        if (not current_cascade or
                (entry.timestamp - current_cascade["last_error"]).total_seconds() > time_window):
            if current_cascade and len(current_cascade["services"]) > 1:
                cascades.append({
                    "start_time": current_cascade["start_time"].isoformat(),
                    "services": current_cascade["services"],
                    "error_count": current_cascade["error_count"],
                    "duration": (current_cascade["last_error"] -
                                 current_cascade["start_time"]).total_seconds()
                })
            current_cascade = {
                "start_time": entry.timestamp,
                "last_error": entry.timestamp,
                "services": [entry.service],
                "error_count": 1
            }
        else:
            # Update error cascade if the service of the current entry is
            # different from the last recorded service
            if entry.service != current_cascade["services"][-1]:
                current_cascade["services"].append(entry.service)
            current_cascade["last_error"] = entry.timestamp
            current_cascade["error_count"] += 1

    if current_cascade and len(current_cascade["services"]) > 1:
        cascades.append({
            "start_time": current_cascade["start_time"].isoformat(),
            "services": current_cascade["services"],
            "error_count": current_cascade["error_count"],
            "duration": (current_cascade["last_error"] -
                         current_cascade["start_time"]).total_seconds()
        })

    return cascades
