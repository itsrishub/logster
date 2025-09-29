use chrono::DateTime;
use ahash::{AHashMap, AHashSet};
use clap::{Parser, ValueEnum};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

// use std::sync::Arc;

use rayon::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Log files to analyze
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Search for pattern in logs
    #[arg(long)]
    search: Option<String>,

    /// Extract errors and warnings
    #[arg(long)]
    errors: bool,

    /// Show statistics
    #[arg(long)]
    stats: bool,

    /// Filter logs from this time (ISO format)
    #[arg(long)]
    start_time: Option<String>,

    /// Filter logs until this time (ISO format)
    #[arg(long)]
    end_time: Option<String>,

    /// Export results to file
    #[arg(long)]
    export: Option<PathBuf>,

    /// Export format
    #[arg(long, value_enum, default_value = "json")]
    export_format: ExportFormat,

    /// Group logs by regex pattern
    #[arg(long)]
    group_by: Option<String>,

    /// Case-sensitive search
    #[arg(long)]
    case_sensitive: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ExportFormat {
    Json,
    Csv,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    file: String,
    line_number: usize,
    raw: String,
    parsed: ParsedLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParsedLog {
    raw_line: String,
    format: String,
    timestamp: Option<String>,
    level: Option<String>,
    ip: Option<String>,
    ip_addresses: Option<Vec<String>>,
    status: Option<String>,
    method: Option<String>,
    path: Option<String>,
    protocol: Option<String>,
    size: Option<String>,
    referer: Option<String>,
    user_agent: Option<String>,
    urls: Option<Vec<String>>,
    message: Option<String>,
}

struct LogPatterns {
    apache_common: Regex,
    apache_combined: Regex,
    nginx: Regex,
    syslog: Regex,
    error_pattern: Regex,
    timestamp_iso: Regex,
    ip_address: Regex,
    url: Regex,
    json_log: Regex,
}

impl LogPatterns {
    fn new() -> Self {
        LogPatterns {
            apache_common: Regex::new(
                r#"^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)"#
            ).unwrap(),
            apache_combined: Regex::new(
                r#"^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"#
            ).unwrap(),
            nginx: Regex::new(
                r#"^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"#
            ).unwrap(),
            syslog: Regex::new(
                r"^(?P<timestamp>\S+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)"
            ).unwrap(),
            error_pattern: Regex::new(
                r"(?i)(?P<level>error|critical|fatal|exception|fail|warn|warning)"
            ).unwrap(),
            timestamp_iso: Regex::new(
                r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
            ).unwrap(),
            ip_address: Regex::new(
                r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b"
            ).unwrap(),
            url: Regex::new(
                r"(?P<url>https?://[^\s]+)"
            ).unwrap(),
            json_log: Regex::new(
                r"^\s*\{.*\}\s*$"
            ).unwrap(),
        }
    }
}

struct LogAnalyzer {
    files: Vec<PathBuf>,
    logs: Vec<LogEntry>,
    patterns: LogPatterns,
}

impl LogAnalyzer {
    fn new(files: Vec<PathBuf>) -> Self {
        LogAnalyzer {
            files,
            logs: Vec::new(),
            patterns: LogPatterns::new(),
        }
    }

    fn load_files(&mut self) -> io::Result<()> {
        for file_path in &self.files {
            if !file_path.exists() {
                eprintln!("Warning: File {:?} does not exist", file_path);
                continue;
            }

            let file = File::open(file_path)?;
            let reader = BufReader::new(file);
            let file_path_str = file_path.to_string_lossy().to_string();

            for (line_num, line_result) in reader.lines().enumerate() {
                if let Ok(line) = line_result {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let parsed = self.parse_line(trimmed);
                        self.logs.push(LogEntry {
                            file: file_path_str.clone(),
                            line_number: line_num + 1,
                            raw: trimmed.to_string(),
                            parsed,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    // fn process_file(&self, file_path: &Path) -> io::Result<Vec<LogEntry>> {
    //     let file = File::open(file_path)?;
    //     let reader = BufReader::with_capacity(64 * 1024, file); // Larger buffer
    //     let file_path_arc = Arc::from(file_path.to_string_lossy().as_ref());
        
    //     let entries: Vec<LogEntry> = reader
    //         .lines()
    //         .enumerate()
    //         .par_bridge() // Parallel line processing
    //         .filter_map(|(line_num, line_result)| {
    //             match line_result {
    //                 Ok(line) => {
    //                     let trimmed = line.trim();
    //                     if trimmed.is_empty() {
    //                         None
    //                     } else {
    //                         let parsed = Self::parse_line(trimmed);
    //                         Some(LogEntry {
    //                             file: Arc::clone(&file_path_arc),
    //                             line_number: line_num + 1,
    //                             raw: Arc::from(trimmed),
    //                             parsed,
    //                         })
    //                     }
    //                 }
    //                 Err(_) => None,
    //             }
    //         })
    //         .collect();

    //     Ok(entries)
    // }

    fn parse_line(&self, line: &str) -> ParsedLog {
        let mut parsed = ParsedLog {
            raw_line: line.to_string(),
            format: "unknown".to_string(),
            timestamp: None,
            level: None,
            ip: None,
            ip_addresses: None,
            status: None,
            method: None,
            path: None,
            protocol: None,
            size: None,
            referer: None,
            user_agent: None,
            urls: None,
            message: None,
        };

        // Try JSON format first
        if self.patterns.json_log.is_match(line) {
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(line) {
                parsed.format = "json".to_string();
                // Extract common fields from JSON
                if let Some(obj) = json_value.as_object() {
                    if let Some(ts) = obj.get("timestamp").and_then(|v| v.as_str()) {
                        parsed.timestamp = Some(ts.to_string());
                    }
                    if let Some(level) = obj.get("level").and_then(|v| v.as_str()) {
                        parsed.level = Some(level.to_uppercase());
                    }
                    if let Some(msg) = obj.get("message").and_then(|v| v.as_str()) {
                        parsed.message = Some(msg.to_string());
                    }
                }
                return parsed;
            }
        }

        // Apache Combined format
        if let Some(caps) = self.patterns.apache_combined.captures(line) {
            parsed.format = "apache_combined".to_string();
            parsed.ip = caps.name("ip").map(|m| m.as_str().to_string());
            parsed.timestamp = caps.name("timestamp").map(|m| m.as_str().to_string());
            parsed.method = caps.name("method").map(|m| m.as_str().to_string());
            parsed.path = caps.name("path").map(|m| m.as_str().to_string());
            parsed.protocol = caps.name("protocol").map(|m| m.as_str().to_string());
            parsed.status = caps.name("status").map(|m| m.as_str().to_string());
            parsed.size = caps.name("size").map(|m| m.as_str().to_string());
            parsed.referer = caps.name("referer").map(|m| m.as_str().to_string());
            parsed.user_agent = caps.name("user_agent").map(|m| m.as_str().to_string());
            return parsed;
        }

        // Apache Common format
        if let Some(caps) = self.patterns.apache_common.captures(line) {
            parsed.format = "apache_common".to_string();
            parsed.ip = caps.name("ip").map(|m| m.as_str().to_string());
            parsed.timestamp = caps.name("timestamp").map(|m| m.as_str().to_string());
            parsed.method = caps.name("method").map(|m| m.as_str().to_string());
            parsed.path = caps.name("path").map(|m| m.as_str().to_string());
            parsed.protocol = caps.name("protocol").map(|m| m.as_str().to_string());
            parsed.status = caps.name("status").map(|m| m.as_str().to_string());
            parsed.size = caps.name("size").map(|m| m.as_str().to_string());
            return parsed;
        }

        // Try Nginx format
        if let Some(caps) = self.patterns.nginx.captures(line) {
            parsed.format = "nginx".to_string();
            parsed.ip = caps.name("ip").map(|m| m.as_str().to_string());
            parsed.timestamp = caps.name("timestamp").map(|m| m.as_str().to_string());
            parsed.method = caps.name("method").map(|m| m.as_str().to_string());
            parsed.path = caps.name("path").map(|m| m.as_str().to_string());
            parsed.protocol = caps.name("protocol").map(|m| m.as_str().to_string());
            parsed.status = caps.name("status").map(|m| m.as_str().to_string());
            parsed.size = caps.name("size").map(|m| m.as_str().to_string());
            parsed.referer = caps.name("referer").map(|m| m.as_str().to_string());
            parsed.user_agent = caps.name("user_agent").map(|m| m.as_str().to_string());
            return parsed;
        }

        // Syslog format
        if let Some(caps) = self.patterns.syslog.captures(line) {
            parsed.format = "syslog".to_string();
            parsed.timestamp = caps.name("timestamp").map(|m| m.as_str().to_string());
            parsed.message = caps.name("message").map(|m| m.as_str().to_string());
        }

        // Extract common elements for unknown formats
        // Extract timestamp
        if let Some(caps) = self.patterns.timestamp_iso.captures(line) {
            parsed.timestamp = caps.name("timestamp").map(|m| m.as_str().to_string());
        }

        // Extract IP addresses
        let ips: Vec<String> = self.patterns.ip_address
            .captures_iter(line)
            .filter_map(|caps| caps.name("ip").map(|m| m.as_str().to_string()))
            .collect();
        if !ips.is_empty() {
            parsed.ip_addresses = Some(ips);
        }

        // Extract error level
        if let Some(caps) = self.patterns.error_pattern.captures(line) {
            parsed.level = caps.name("level").map(|m| m.as_str().to_uppercase());
        }

        // Extract URLs
        let urls: Vec<String> = self.patterns.url
            .captures_iter(line)
            .filter_map(|caps| caps.name("url").map(|m| m.as_str().to_string()))
            .collect();
        if !urls.is_empty() {
            parsed.urls = Some(urls);
        }

        parsed
    }

    fn search(&self, pattern: &str, case_sensitive: bool) -> Vec<LogEntry> {
        let regex = if case_sensitive {
            Regex::new(pattern).unwrap()
        } else {
            Regex::new(&format!("(?i){}", pattern)).unwrap()
        };

        self.logs
            .par_iter()
            .filter(|log| regex.is_match(&log.raw))
            .cloned()
            .collect()
    }

    fn filter_by_time(&self, start_time: Option<&str>, end_time: Option<&str>) -> Vec<LogEntry> {
        let start_dt = start_time.and_then(|s| DateTime::parse_from_rfc3339(s).ok());
        let end_dt = end_time.and_then(|s| DateTime::parse_from_rfc3339(s).ok());

        self.logs
            .par_iter()
            .filter(|log| {
                if let Some(ref timestamp) = log.parsed.timestamp {
                    if let Ok(log_time) = DateTime::parse_from_rfc3339(timestamp) {
                        if let Some(ref start) = start_dt {
                            if log_time < *start {
                                return false;
                            }
                        }
                        if let Some(ref end) = end_dt {
                            if log_time > *end {
                                return false;
                            }
                        }
                        return true;
                    }
                }
                false
            })
            .cloned()
            .collect()
    }

    fn extract_errors(&self, include_warnings: bool) -> Vec<LogEntry> {
        let mut levels = vec!["ERROR", "CRITICAL", "FATAL", "EXCEPTION", "FAIL"];
        if include_warnings {
            levels.extend(&["WARN", "WARNING"]);
        }

        self.logs
            .par_iter()
            .filter(|log| {
                if let Some(ref level) = log.parsed.level {
                    return levels.contains(&level.as_str());
                }
                levels.par_iter().any(|l| log.raw.to_uppercase().contains(l))
            })
            .cloned()
            .collect()
    }

    fn group_by_pattern(&self, pattern: &str) -> AHashMap<String, Vec<LogEntry>> {
        let regex = Regex::new(pattern).unwrap();
        let mut groups = AHashMap::new();

        for log in &self.logs {
            if let Some(captures) = regex.captures(&log.raw) {
                let key = if captures.len() > 1 {
                    captures.get(1).map(|m| m.as_str().to_string())
                } else {
                    captures.get(0).map(|m| m.as_str().to_string())
                };

                if let Some(key) = key {
                    groups.entry(key).or_insert_with(Vec::new).push(log.clone());
                }
            }
        }

        groups
    }

    fn get_statistics(&self) -> Statistics {
        let mut stats = Statistics::default();
        stats.total_lines = self.logs.len();
        
        let mut files = AHashSet::new();
        let mut formats = AHashMap::new();
        let mut error_levels = AHashMap::new();
        let mut status_codes = AHashMap::new();
        let mut ip_addresses = AHashMap::new();
        let mut methods = AHashMap::new();
        let mut paths = AHashMap::new();
        let mut user_agents = AHashMap::new();

        for log in &self.logs {
            files.insert(log.file.clone());
            
            *formats.entry(log.parsed.format.clone()).or_insert(0) += 1;

            if let Some(ref level) = log.parsed.level {
                *error_levels.entry(level.clone()).or_insert(0) += 1;
                if ["ERROR", "CRITICAL", "FATAL", "WARN", "WARNING"].contains(&level.as_str()) {
                    stats.errors_warnings += 1;
                }
            }

            if let Some(ref status) = log.parsed.status {
                *status_codes.entry(status.clone()).or_insert(0) += 1;
            }

            if let Some(ref ip) = log.parsed.ip {
                *ip_addresses.entry(ip.clone()).or_insert(0) += 1;
            } else if let Some(ref ips) = log.parsed.ip_addresses {
                for ip in ips {
                    *ip_addresses.entry(ip.clone()).or_insert(0) += 1;
                }
            }

            if let Some(ref method) = log.parsed.method {
                *methods.entry(method.clone()).or_insert(0) += 1;
            }

            if let Some(ref path) = log.parsed.path {
                *paths.entry(path.clone()).or_insert(0) += 1;
            }

            if let Some(ref ua) = log.parsed.user_agent {
                *user_agents.entry(ua.clone()).or_insert(0) += 1;
            }
        }

        stats.files_processed = files.len();
        stats.formats_detected = formats;
        stats.error_levels = error_levels;
        stats.status_codes = status_codes;
        stats.ip_addresses = ip_addresses;
        stats.methods = methods;
        stats.paths = paths;
        stats.user_agents = user_agents;

        stats
    }

    fn export_results(&self, results: &[LogEntry], output_file: &Path, format: ExportFormat) -> io::Result<()> {
        match format {
            ExportFormat::Json => {
                let json = serde_json::to_string_pretty(&results)?;
                std::fs::write(output_file, json)?;
            }
            ExportFormat::Csv => {
                let mut wtr = csv::Writer::from_path(output_file)?;
                for entry in results {
                    wtr.write_record(&[
                        &entry.file,
                        &entry.line_number.to_string(),
                        &entry.raw,
                        &entry.parsed.format,
                        entry.parsed.level.as_deref().unwrap_or(""),
                        entry.parsed.ip.as_deref().unwrap_or(""),
                        entry.parsed.status.as_deref().unwrap_or(""),
                        entry.parsed.path.as_deref().unwrap_or(""),
                    ])?;
                }
                wtr.flush()?;
            }
            ExportFormat::Text => {
                let mut file = File::create(output_file)?;
                for entry in results {
                    writeln!(file, "[{}:{}] {}", entry.file, entry.line_number, entry.raw)?;
                }
            }
        }
        println!("Results exported to {:?}", output_file);
        Ok(())
    }
}

#[derive(Default, Debug)]
struct Statistics {
    total_lines: usize,
    files_processed: usize,
    errors_warnings: usize,
    formats_detected: AHashMap<String, usize>,
    error_levels: AHashMap<String, usize>,
    status_codes: AHashMap<String, usize>,
    ip_addresses: AHashMap<String, usize>,
    methods: AHashMap<String, usize>,
    paths: AHashMap<String, usize>,
    user_agents: AHashMap<String, usize>,
}

impl Statistics {
    fn print(&self) {
        println!("\n{}", "=".repeat(50));
        println!("LOG STATISTICS");
        println!("{}", "=".repeat(50));
        println!("Total log entries: {}", self.total_lines);
        println!("Files processed: {}", self.files_processed);
        println!("Errors/Warnings: {}", self.errors_warnings);

        println!("\nLog formats detected:");
        let mut formats: Vec<_> = self.formats_detected.par_iter().collect();
        formats.sort_by(|a, b| b.1.cmp(a.1));
        for (format, count) in formats.iter().take(10) {
            println!("  {}: {}", format, count);
        }

        if !self.error_levels.is_empty() {
            println!("\nError levels:");
            let mut levels: Vec<_> = self.error_levels.par_iter().collect();
            levels.sort_by(|a, b| b.1.cmp(a.1));
            for (level, count) in levels {
                println!("  {}: {}", level, count);
            }
        }

        if !self.status_codes.is_empty() {
            println!("\nTop HTTP status codes:");
            let mut codes: Vec<_> = self.status_codes.par_iter().collect();
            codes.sort_by(|a, b| b.1.cmp(a.1));
            for (code, count) in codes.iter().take(10) {
                println!("  {}: {}", code, count);
            }
        }

        if !self.ip_addresses.is_empty() {
            println!("\nTop IP addresses:");
            let mut ips: Vec<_> = self.ip_addresses.par_iter().collect();
            ips.sort_by(|a, b| b.1.cmp(a.1));
            for (ip, count) in ips.iter().take(5) {
                println!("  {}: {} requests", ip, count);
            }
        }

        if !self.paths.is_empty() {
            println!("\nTop requested paths:");
            let mut paths: Vec<_> = self.paths.par_iter().collect();
            paths.sort_by(|a, b| b.1.cmp(a.1));
            for (path, count) in paths.iter().take(5) {
                println!("  {}: {} requests", path, count);
            }
        }

        if !self.methods.is_empty() {
            println!("\nHTTP methods:");
            let mut methods: Vec<_> = self.methods.par_iter().collect();
            methods.sort_by(|a, b| b.1.cmp(a.1));
            for (method, count) in methods {
                println!("  {}: {}", method, count);
            }
        }
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut analyzer = LogAnalyzer::new(args.files);
    analyzer.load_files()?;

    if analyzer.logs.is_empty() {
        eprintln!("No logs loaded. Please check your file paths.");
        return Ok(());
    }

    println!("Loaded {} log entries from {} file(s)", 
            analyzer.logs.len(), 
            analyzer.files.len());

    let mut results = None;

    // Search operation
    if let Some(ref search_pattern) = args.search {
        let search_results = analyzer.search(search_pattern, args.case_sensitive);
        println!("\nFound {} matches for '{}':", search_results.len(), search_pattern);
        for result in search_results.iter().take(10) {
            let truncated = if result.raw.len() > 100 {
                format!("{}...", &result.raw[..100])
            } else {
                result.raw.clone()
            };
            println!("  [{}:{}] {}", result.file, result.line_number, truncated);
        }
        if search_results.len() > 10 {
            println!("  ... and {} more matches", search_results.len() - 10);
        }
        results = Some(search_results);
    }

    // Extract errors
    if args.errors {
        let errors = analyzer.extract_errors(true);
        println!("\nFound {} errors/warnings:", errors.len());
        for error in errors.iter().take(10) {
            let level = error.parsed.level.as_deref().unwrap_or("ERROR");
            let truncated = if error.raw.len() > 100 {
                format!("{}...", &error.raw[..100])
            } else {
                error.raw.clone()
            };
            println!("  [{}] {}", level, truncated);
        }
        if errors.len() > 10 {
            println!("  ... and {} more errors/warnings", errors.len() - 10);
        }
        if results.is_none() {
            results = Some(errors);
        }
    }

    // Time filtering
    if args.start_time.is_some() || args.end_time.is_some() {
        let filtered = analyzer.filter_by_time(
            args.start_time.as_deref(),
            args.end_time.as_deref()
        );
        println!("\nFound {} logs in specified time range", filtered.len());
        if results.is_none() {
            results = Some(filtered);
        }
    }

    // Group by pattern
    if let Some(ref group_pattern) = args.group_by {
        let groups = analyzer.group_by_pattern(group_pattern);
        println!("\nGrouped logs into {} groups:", groups.len());
        let mut groups_vec: Vec<_> = groups.par_iter().collect();
        groups_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (key, items) in groups_vec.iter().take(10) {
            println!("  '{}': {} entries", key, items.len());
        }
    }

    // Show statistics
    if args.stats {
        let stats = analyzer.get_statistics();
        stats.print();
    }

    // Export results
    if let Some(ref export_path) = args.export {
        if let Some(ref results_to_export) = results {
            analyzer.export_results(results_to_export, export_path, args.export_format)?;
        } else {
            eprintln!("No results to export. Use --search, --errors, or time filters to generate results.");
        }
    }

    Ok(())
}