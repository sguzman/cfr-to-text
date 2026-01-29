use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use globset::{Glob, GlobSet, GlobSetBuilder};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "cfr-to-text", version, about = "Extract text from CFR XML files")]
struct Cli {
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    #[arg(long, global = true, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Pretty)]
    log_format: LogFormat,

    #[arg(long, global = true, value_name = "FILE")]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Extract text from CFR XML inputs
    Extract(ExtractArgs),
    /// Write a default config file
    InitConfig(InitConfigArgs),
    /// Print the effective config as TOML
    PrintConfig(PrintConfigArgs),
}

#[derive(Args, Debug)]
struct ExtractArgs {
    /// Input XML files
    #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
    inputs: Vec<PathBuf>,

    /// Input directories to scan
    #[arg(long, value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    input_dir: Vec<PathBuf>,

    /// Recurse into subdirectories
    #[arg(long, action = ArgAction::SetTrue)]
    recursive: bool,

    /// Do not recurse into subdirectories
    #[arg(long = "no-recursive", action = ArgAction::SetTrue)]
    no_recursive: bool,

    /// Follow symlinks while walking directories
    #[arg(long, action = ArgAction::SetTrue)]
    follow_symlinks: bool,

    /// Do not follow symlinks while walking directories
    #[arg(long = "no-follow-symlinks", action = ArgAction::SetTrue)]
    no_follow_symlinks: bool,

    /// Glob filters to apply to input paths
    #[arg(long, value_name = "GLOB")]
    glob: Vec<String>,

    /// Output directory (one output file per input file)
    #[arg(long, value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    output_dir: Option<PathBuf>,

    /// Output file (all inputs combined)
    #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Overwrite existing output files
    #[arg(long, action = ArgAction::SetTrue)]
    overwrite: bool,

    /// Split output files larger than this size (bytes)
    #[arg(long, value_name = "BYTES")]
    split_max_bytes: Option<u64>,

    /// Disable output file splitting
    #[arg(long = "no-split", action = ArgAction::SetTrue)]
    no_split: bool,

    /// Minimum text length to emit
    #[arg(long, value_name = "N")]
    min_text_len: Option<usize>,

    /// Max XML depth to read
    #[arg(long, value_name = "N")]
    max_depth: Option<usize>,

    /// Include only these elements (repeatable)
    #[arg(long, value_name = "NAME")]
    include_element: Vec<String>,

    /// Exclude these elements (repeatable)
    #[arg(long, value_name = "NAME")]
    exclude_element: Vec<String>,

    /// Treat these elements as headings
    #[arg(long, value_name = "NAME")]
    heading_element: Vec<String>,

    /// Treat these elements as paragraphs
    #[arg(long, value_name = "NAME")]
    paragraph_element: Vec<String>,

    /// Strip leading and trailing whitespace
    #[arg(long, action = ArgAction::SetTrue)]
    strip_whitespace: bool,

    /// Do not strip leading and trailing whitespace
    #[arg(long = "no-strip-whitespace", action = ArgAction::SetTrue)]
    no_strip_whitespace: bool,

    /// Collapse repeated whitespace into single spaces
    #[arg(long, action = ArgAction::SetTrue)]
    collapse_whitespace: bool,

    /// Do not collapse repeated whitespace
    #[arg(long = "no-collapse-whitespace", action = ArgAction::SetTrue)]
    no_collapse_whitespace: bool,

    /// Preserve line breaks when collapsing whitespace
    #[arg(long, action = ArgAction::SetTrue)]
    preserve_line_breaks: bool,

    /// Do not preserve line breaks when collapsing whitespace
    #[arg(long = "no-preserve-line-breaks", action = ArgAction::SetTrue)]
    no_preserve_line_breaks: bool,

    /// Include element name in output (jsonl)
    #[arg(long, action = ArgAction::SetTrue)]
    emit_element: bool,

    /// Include element path in output (jsonl)
    #[arg(long, action = ArgAction::SetTrue)]
    emit_path: bool,

    /// Include source file path in output (jsonl)
    #[arg(long, action = ArgAction::SetTrue)]
    emit_source: bool,

    /// Output record delimiter (plain text)
    #[arg(long, value_name = "DELIM")]
    record_delimiter: Option<String>,
}

#[derive(Args, Debug)]
struct InitConfigArgs {
    /// Path to write the config file
    #[arg(long, value_name = "FILE", default_value = "cfr-to-text.toml")]
    path: PathBuf,

    /// Overwrite if the file already exists
    #[arg(long, action = ArgAction::SetTrue)]
    overwrite: bool,
}

#[derive(Args, Debug)]
struct PrintConfigArgs {
    /// Print defaults only, without reading a config file
    #[arg(long, action = ArgAction::SetTrue)]
    defaults: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    input: InputConfig,
    parse: ParseConfig,
    emit: EmitConfig,
    output: OutputConfig,
    logging: LoggingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InputConfig {
    paths: Vec<PathBuf>,
    recursive: bool,
    follow_symlinks: bool,
    globs: Vec<String>,
    xml_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParseConfig {
    include_elements: Vec<String>,
    exclude_elements: Vec<String>,
    heading_elements: Vec<String>,
    paragraph_elements: Vec<String>,
    max_depth: Option<usize>,
    min_text_len: usize,
    strip_whitespace: bool,
    collapse_whitespace: bool,
    preserve_line_breaks: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EmitConfig {
    include_element_name: bool,
    include_element_path: bool,
    include_source_file: bool,
    record_delimiter: String,
    heading_prefix: String,
    paragraph_prefix: String,
    heading_blank_line: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OutputConfig {
    output_dir: Option<PathBuf>,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    overwrite: bool,
    #[serde(default = "default_split_max_bytes")]
    split_max_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LoggingConfig {
    level: String,
    format: LogFormat,
    file: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, ValueEnum)]
enum OutputFormat {
    Plain,
    Jsonl,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, ValueEnum)]
enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Serialize)]
struct TextRecord {
    text: String,
    kind: String,
    element: Option<String>,
    path: Option<String>,
    source: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            input: InputConfig {
                paths: Vec::new(),
                recursive: true,
                follow_symlinks: false,
                globs: vec!["**/*.xml".to_string()],
                xml_only: true,
            },
            parse: ParseConfig {
                include_elements: Vec::new(),
                exclude_elements: Vec::new(),
                heading_elements: vec!["HD".to_string(), "HED".to_string()],
                paragraph_elements: vec!["P".to_string(), "FP".to_string()],
                max_depth: None,
                min_text_len: 1,
                strip_whitespace: true,
                collapse_whitespace: true,
                preserve_line_breaks: false,
            },
            emit: EmitConfig {
                include_element_name: true,
                include_element_path: false,
                include_source_file: true,
                record_delimiter: "\n".to_string(),
                heading_prefix: "# ".to_string(),
                paragraph_prefix: "".to_string(),
                heading_blank_line: true,
            },
            output: OutputConfig {
                output_dir: None,
                output_file: None,
                format: OutputFormat::Plain,
                overwrite: false,
                split_max_bytes: Some(1_048_576),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: LogFormat::Pretty,
                file: None,
            },
        }
    }
}

fn default_split_max_bytes() -> Option<u64> {
    Some(1_048_576)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.command, Commands::InitConfig(_)) {
        let logging = LoggingConfig {
            level: cli.log_level.clone(),
            format: cli.log_format,
            file: cli.log_file.clone(),
        };
        init_logging(&logging)?;
        if let Commands::InitConfig(args) = cli.command {
            write_default_config(&args.path, args.overwrite)?;
        }
        return Ok(());
    }

    let mut config = if let Commands::PrintConfig(args) = &cli.command {
        if args.defaults {
            Config::default()
        } else {
            load_config(cli.config.as_deref())?
        }
    } else {
        load_config(cli.config.as_deref())?
    };

    apply_global_overrides(&mut config, &cli);
    normalize_output_config(&mut config);
    init_logging(&config.logging)?;

    match cli.command {
        Commands::Extract(args) => {
            apply_extract_overrides(&mut config, &args);
            normalize_output_config(&mut config);
            run_extract(&config, &args)
        }
        Commands::PrintConfig(_) => print_config(&config),
        Commands::InitConfig(_) => Ok(()),
    }
}

fn write_default_config(path: &Path, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        return Err(anyhow!("config file already exists: {}", path.display()));
    }
    let config = Config::default();
    let toml = toml::to_string_pretty(&config).context("serialize default config")?;
    fs::write(path, toml).with_context(|| format!("write config to {}", path.display()))?;
    info!("wrote default config to {}", path.display());
    Ok(())
}

fn load_config(path: Option<&Path>) -> Result<Config> {
    let path = path.unwrap_or_else(|| Path::new("cfr-to-text.toml"));
    if !path.exists() {
        info!("config file not found at {}, using defaults", path.display());
        return Ok(Config::default());
    }
    let mut contents = String::new();
    File::open(path)
        .with_context(|| format!("open config {}", path.display()))?
        .read_to_string(&mut contents)
        .context("read config file")?;
    let config: Config = toml::from_str(&contents).context("parse config file")?;
    info!("loaded config from {}", path.display());
    Ok(config)
}

fn print_config(config: &Config) -> Result<()> {
    let toml = toml::to_string_pretty(config).context("serialize config")?;
    println!("{}", toml);
    Ok(())
}

fn apply_global_overrides(config: &mut Config, cli: &Cli) {
    config.logging.level = cli.log_level.clone();
    config.logging.format = cli.log_format;
    if cli.log_file.is_some() {
        config.logging.file = cli.log_file.clone();
    }
}

fn apply_extract_overrides(config: &mut Config, args: &ExtractArgs) {
    if !args.inputs.is_empty() {
        config.input.paths = args.inputs.clone();
    }
    if !args.input_dir.is_empty() {
        config.input.paths.extend(args.input_dir.clone());
    }
    if args.recursive {
        config.input.recursive = true;
    }
    if args.no_recursive {
        config.input.recursive = false;
    }
    if args.follow_symlinks {
        config.input.follow_symlinks = true;
    }
    if args.no_follow_symlinks {
        config.input.follow_symlinks = false;
    }
    if !args.glob.is_empty() {
        config.input.globs = args.glob.clone();
    }
    if let Some(output_dir) = &args.output_dir {
        config.output.output_dir = Some(output_dir.clone());
    }
    if let Some(output_file) = &args.output {
        config.output.output_file = Some(output_file.clone());
    }
    if let Some(format) = args.format {
        config.output.format = format;
    }
    if args.overwrite {
        config.output.overwrite = true;
    }
    if let Some(split_max_bytes) = args.split_max_bytes {
        config.output.split_max_bytes = Some(split_max_bytes);
    }
    if args.no_split {
        config.output.split_max_bytes = None;
    }
    if let Some(min_text_len) = args.min_text_len {
        config.parse.min_text_len = min_text_len;
    }
    if let Some(max_depth) = args.max_depth {
        config.parse.max_depth = Some(max_depth);
    }
    if !args.include_element.is_empty() {
        config.parse.include_elements = args.include_element.clone();
    }
    if !args.exclude_element.is_empty() {
        config.parse.exclude_elements = args.exclude_element.clone();
    }
    if !args.heading_element.is_empty() {
        config.parse.heading_elements = args.heading_element.clone();
    }
    if !args.paragraph_element.is_empty() {
        config.parse.paragraph_elements = args.paragraph_element.clone();
    }
    if args.strip_whitespace {
        config.parse.strip_whitespace = true;
    }
    if args.no_strip_whitespace {
        config.parse.strip_whitespace = false;
    }
    if args.collapse_whitespace {
        config.parse.collapse_whitespace = true;
    }
    if args.no_collapse_whitespace {
        config.parse.collapse_whitespace = false;
    }
    if args.preserve_line_breaks {
        config.parse.preserve_line_breaks = true;
    }
    if args.no_preserve_line_breaks {
        config.parse.preserve_line_breaks = false;
    }
    if args.emit_element {
        config.emit.include_element_name = true;
    }
    if args.emit_path {
        config.emit.include_element_path = true;
    }
    if args.emit_source {
        config.emit.include_source_file = true;
    }
    if let Some(delim) = &args.record_delimiter {
        config.emit.record_delimiter = delim.clone();
    }
}

fn normalize_output_config(config: &mut Config) {
    if let Some(0) = config.output.split_max_bytes {
        config.output.split_max_bytes = None;
    }
}

fn init_logging(config: &LoggingConfig) -> Result<()> {
    let filter = EnvFilter::try_new(config.level.clone())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let writer: BoxMakeWriter = match &config.file {
        Some(path) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("open log file {}", path.display()))?;
            BoxMakeWriter::new(file)
        }
        None => BoxMakeWriter::new(io::stderr),
    };

    let subscriber: Box<dyn tracing::Subscriber + Send + Sync> = match config.format {
        LogFormat::Pretty => Box::new(
            FmtSubscriber::builder()
                .with_env_filter(filter)
                .with_writer(writer)
                .finish(),
        ),
        LogFormat::Json => Box::new(
            FmtSubscriber::builder()
                .with_env_filter(filter)
                .with_writer(writer)
                .json()
                .finish(),
        ),
    };

    tracing::subscriber::set_global_default(subscriber)
        .context("set global tracing subscriber")?;
    Ok(())
}

fn run_extract(config: &Config, args: &ExtractArgs) -> Result<()> {
    debug!(?config, "effective config");
    if config.output.output_dir.is_some() && config.output.output_file.is_some() {
        return Err(anyhow!("cannot set both output_dir and output_file"));
    }

    let input_paths = gather_inputs(config).context("collect input files")?;
    if input_paths.is_empty() {
        return Err(anyhow!("no input XML files found"));
    }

    info!("starting extraction");
    info!("inputs: {}", input_paths.len());
    info!("output format: {:?}", config.output.format);

    let mut total_records = 0usize;
    let start = Utc::now();

    if let Some(output_file) = &config.output.output_file {
        let mut sink = OutputSink::new_file(
            output_file.to_path_buf(),
            config.output.format,
            config.output.overwrite,
            config.output.split_max_bytes,
        )?;
        for path in &input_paths {
            total_records += process_file(path, &mut sink, config)?;
        }
        sink.flush().context("flush output")?;
    } else if let Some(output_dir) = &config.output.output_dir {
        fs::create_dir_all(output_dir)
            .with_context(|| format!("create output dir {}", output_dir.display()))?;
        for path in &input_paths {
            let out_path = output_path_for_input(output_dir, path, config.output.format)?;
            let mut sink = OutputSink::new_file(
                out_path,
                config.output.format,
                config.output.overwrite,
                config.output.split_max_bytes,
            )?;
            total_records += process_file(path, &mut sink, config)?;
            sink.flush().context("flush output")?;
        }
    } else {
        let stdout = io::stdout();
        let mut sink = OutputSink::new_stdout(config.output.format, stdout);
        for path in &input_paths {
            total_records += process_file(path, &mut sink, config)?;
        }
        sink.flush().context("flush stdout")?;
    }

    let elapsed = Utc::now() - start;
    info!("completed extraction");
    info!("records emitted: {}", total_records);
    info!("elapsed seconds: {}", elapsed.num_seconds());

    if args.record_delimiter.is_some() {
        debug!("record delimiter override applied");
    }

    Ok(())
}

fn gather_inputs(config: &Config) -> Result<Vec<PathBuf>> {
    let mut inputs = Vec::new();
    let mut seen = BTreeSet::new();

    let globset = build_globset(&config.input.globs)?;

    for path in &config.input.paths {
        if path.is_file() {
            if is_allowed_file(path, config.input.xml_only, &globset) {
                if seen.insert(path.to_path_buf()) {
                    inputs.push(path.to_path_buf());
                }
            }
        } else if path.is_dir() {
            let walker = WalkDir::new(path)
                .follow_links(config.input.follow_symlinks)
                .max_depth(if config.input.recursive { usize::MAX } else { 1 });
            for entry in walker {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let entry_path = entry.path();
                if is_allowed_file(entry_path, config.input.xml_only, &globset) {
                    let path_buf = entry_path.to_path_buf();
                    if seen.insert(path_buf.clone()) {
                        inputs.push(path_buf);
                    }
                }
            }
        } else {
            warn!("input path does not exist: {}", path.display());
        }
    }

    inputs.sort();
    Ok(inputs)
}

fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    if patterns.is_empty() {
        return Ok(GlobSetBuilder::new().build()?);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    Ok(builder.build()?)
}

fn is_allowed_file(path: &Path, xml_only: bool, globset: &GlobSet) -> bool {
    if xml_only {
        if path.extension().and_then(OsStr::to_str) != Some("xml") {
            return false;
        }
    }
    if globset.is_empty() {
        return true;
    }
    globset.is_match(path)
}

fn create_writer(path: &Path, overwrite: bool) -> Result<BufWriter<File>> {
    if path.exists() && !overwrite {
        return Err(anyhow!("output already exists: {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output dir {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("open output file {}", path.display()))?;
    Ok(BufWriter::new(file))
}

fn output_path_for_input(output_dir: &Path, input: &Path, format: OutputFormat) -> Result<PathBuf> {
    let stem = input
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("invalid input file name: {}", input.display()))?;
    let extension = match format {
        OutputFormat::Plain => "txt",
        OutputFormat::Jsonl => "jsonl",
    };
    Ok(output_dir.join(format!("{}.{}", stem, extension)))
}

fn process_file(path: &Path, sink: &mut OutputSink, config: &Config) -> Result<usize> {
    info!("processing {}", path.display());
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut record_count = 0usize;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = bytes_to_string(e.name().as_ref())?;
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = bytes_to_string(e.name().as_ref())?;
                stack.push(name);
                stack.pop();
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = e.xml_content()?.into_owned();
                if let Some(record) = build_record(&text, &stack, path, config)? {
                    emit_record(sink, &record, config)?;
                    record_count += 1;
                }
            }
            Ok(Event::CData(e)) => {
                let text = e.xml_content()?.into_owned();
                if let Some(record) = build_record(&text, &stack, path, config)? {
                    emit_record(sink, &record, config)?;
                    record_count += 1;
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(anyhow!("xml read error in {}: {}", path.display(), err));
            }
            _ => {}
        }
        buf.clear();
    }

    info!("completed {} ({} records)", path.display(), record_count);
    Ok(record_count)
}

fn bytes_to_string(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|err| anyhow!("invalid utf-8: {}", err))
}

fn build_record(
    text: &str,
    stack: &[String],
    path: &Path,
    config: &Config,
) -> Result<Option<TextRecord>> {
    if stack.is_empty() {
        return Ok(None);
    }

    if let Some(max_depth) = config.parse.max_depth {
        if stack.len() > max_depth {
            return Ok(None);
        }
    }

    let current = stack.last().map(String::as_str).unwrap_or("");

    if !config.parse.include_elements.is_empty()
        && !config.parse.include_elements.iter().any(|v| v == current)
    {
        return Ok(None);
    }

    if config
        .parse
        .exclude_elements
        .iter()
        .any(|v| v == current)
    {
        return Ok(None);
    }

    let normalized = normalize_text(text, &config.parse);
    if normalized.is_none() {
        return Ok(None);
    }
    let normalized = normalized.unwrap();

    if normalized.len() < config.parse.min_text_len {
        return Ok(None);
    }

    let kind = if config
        .parse
        .heading_elements
        .iter()
        .any(|v| v == current)
    {
        "heading".to_string()
    } else if config
        .parse
        .paragraph_elements
        .iter()
        .any(|v| v == current)
    {
        "paragraph".to_string()
    } else {
        "text".to_string()
    };

    let element = if config.emit.include_element_name {
        Some(current.to_string())
    } else {
        None
    };

    let path_str = if config.emit.include_element_path {
        Some(stack.join("/"))
    } else {
        None
    };

    let source = if config.emit.include_source_file {
        Some(path.display().to_string())
    } else {
        None
    };

    Ok(Some(TextRecord {
        text: normalized,
        kind,
        element,
        path: path_str,
        source,
    }))
}

fn normalize_text(input: &str, parse: &ParseConfig) -> Option<String> {
    let mut s = input.to_string();

    if parse.strip_whitespace {
        s = s.trim().to_string();
    }

    if parse.collapse_whitespace {
        if parse.preserve_line_breaks {
            let mut lines = Vec::new();
            for line in s.lines() {
                let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
                lines.push(collapsed);
            }
            s = lines.join("\n");
        } else {
            s = s.split_whitespace().collect::<Vec<_>>().join(" ");
        }
    }

    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn emit_record(sink: &mut OutputSink, record: &TextRecord, config: &Config) -> Result<()> {
    let rendered = match config.output.format {
        OutputFormat::Plain => render_plain(record, &config.emit),
        OutputFormat::Jsonl => render_jsonl(record),
    }?;
    sink.write_record(&rendered)
}

fn render_plain(record: &TextRecord, emit: &EmitConfig) -> Result<String> {
    let mut buffer = String::new();

    if record.kind == "heading" && emit.heading_blank_line {
        buffer.push_str("\n");
    }

    match record.kind.as_str() {
        "heading" => buffer.push_str(&emit.heading_prefix),
        "paragraph" => buffer.push_str(&emit.paragraph_prefix),
        _ => {}
    }

    buffer.push_str(&record.text);
    buffer.push_str(&emit.record_delimiter);

    Ok(buffer)
}

fn render_jsonl(record: &TextRecord) -> Result<String> {
    let json = serde_json::to_string(record).context("serialize json record")?;
    Ok(format!("{}\n", json))
}

enum OutputTarget {
    SingleFile,
    Stdout,
}

struct OutputSink {
    target: OutputTarget,
    format: OutputFormat,
    overwrite: bool,
    split_max_bytes: Option<u64>,
    writer: WriterKind,
    bytes_written: u64,
    part_index: u32,
    base_path: Option<PathBuf>,
}

enum WriterKind {
    File(BufWriter<File>),
    Stdout(BufWriter<io::Stdout>),
}

impl OutputSink {
    fn new_file(
        path: PathBuf,
        format: OutputFormat,
        overwrite: bool,
        split_max_bytes: Option<u64>,
    ) -> Result<Self> {
        let writer = create_writer(&path, overwrite)?;
        Ok(Self {
            target: OutputTarget::SingleFile,
            format,
            overwrite,
            split_max_bytes,
            writer: WriterKind::File(writer),
            bytes_written: 0,
            part_index: 0,
            base_path: Some(path),
        })
    }

    fn new_stdout(format: OutputFormat, stdout: io::Stdout) -> Self {
        Self {
            target: OutputTarget::Stdout,
            format,
            overwrite: false,
            split_max_bytes: None,
            writer: WriterKind::Stdout(BufWriter::new(stdout)),
            bytes_written: 0,
            part_index: 0,
            base_path: None,
        }
    }

    fn write_record(&mut self, record: &str) -> Result<()> {
        if let Some(limit) = self.split_max_bytes {
            if matches!(self.target, OutputTarget::SingleFile)
                && self.bytes_written > 0
                && self.bytes_written + record.as_bytes().len() as u64 > limit
            {
                self.rotate_file()?;
            }
        }

        match &mut self.writer {
            WriterKind::File(writer) => writer
                .write_all(record.as_bytes())
                .context("write output")?,
            WriterKind::Stdout(writer) => writer
                .write_all(record.as_bytes())
                .context("write output")?,
        }

        self.bytes_written += record.as_bytes().len() as u64;
        Ok(())
    }

    fn rotate_file(&mut self) -> Result<()> {
        let base = self
            .base_path
            .as_ref()
            .ok_or_else(|| anyhow!("missing base output path"))?;
        self.part_index += 1;
        let rotated = split_path(base, self.part_index, self.format)?;
        info!(
            "splitting output at {} bytes -> {}",
            self.bytes_written,
            rotated.display()
        );
        self.writer = WriterKind::File(create_writer(&rotated, self.overwrite)?);
        self.bytes_written = 0;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        match &mut self.writer {
            WriterKind::File(writer) => writer.flush().context("flush output"),
            WriterKind::Stdout(writer) => writer.flush().context("flush output"),
        }
    }
}

fn split_path(base: &Path, part_index: u32, format: OutputFormat) -> Result<PathBuf> {
    let stem = base
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("invalid output file name: {}", base.display()))?;
    let extension = match format {
        OutputFormat::Plain => "txt",
        OutputFormat::Jsonl => "jsonl",
    };
    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{}.part{:03}.{}", stem, part_index, extension)))
}
