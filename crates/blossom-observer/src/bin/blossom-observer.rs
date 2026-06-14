use std::path::PathBuf;
use std::sync::Arc;

use blossom_observer::{ObserverCollector, analyze_events};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type SharedOutput = Option<Arc<std::sync::Mutex<std::io::BufWriter<std::fs::File>>>>;
const OUTPUT_BATCH_BYTES: usize = 1 << 20;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-observer",
    about = "Collect and analyze Blossom distributed protocol telemetry"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:7717")]
        bind: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:7718")]
        ui_bind: String,
        #[arg(long, default_value_t = false)]
        no_ui: bool,
    },
    Analyze {
        #[arg(long)]
        input: PathBuf,
    },
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    match args.command {
        Command::Serve {
            bind,
            output,
            ui_bind,
            no_ui,
        } => serve(bind, output, (!no_ui).then_some(ui_bind)).await,
        Command::Analyze { input } => analyze(input),
    }
}

async fn serve(bind: String, output: Option<PathBuf>, ui_bind: Option<String>) -> MainResult<()> {
    let listener = TcpListener::bind(&bind).await?;
    let collector = Arc::new(ObserverCollector::default());
    let ui_listener = match ui_bind {
        Some(bind) => Some((bind.clone(), TcpListener::bind(&bind).await?)),
        None => None,
    };
    let output = match output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Some(Arc::new(std::sync::Mutex::new(std::io::BufWriter::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?,
            ))))
        }
        None => None,
    };
    eprintln!("blossom-observer listening on {bind}");
    let ui_task = match ui_listener {
        Some((ui_bind, ui_listener)) => {
            let collector = Arc::clone(&collector);
            eprintln!("blossom-observer dashboard listening on http://{ui_bind}");
            Some(tokio::spawn(async move {
                if let Err(err) = serve_ui(ui_listener, collector).await {
                    eprintln!("observer dashboard failed: {err}");
                }
            }))
        }
        None => None,
    };

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let collector = Arc::clone(&collector);
                let output = output.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, collector, output).await {
                        eprintln!("telemetry connection {peer} failed: {err}");
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                let analysis = collector.analysis();
                println!("{}", serde_json::to_string_pretty(&analysis)?);
                break;
            }
        }
    }

    if let Some(ui_task) = ui_task {
        ui_task.abort();
    }

    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    collector: Arc<ObserverCollector>,
    output: SharedOutput,
) -> MainResult<()> {
    let mut lines = BufReader::new(stream).lines();
    let mut output_batch = Vec::with_capacity(OUTPUT_BATCH_BYTES);
    while let Some(line) = lines.next_line().await? {
        collector.ingest_json_line(&line)?;
        if let Some(output) = output.as_ref() {
            output_batch.extend_from_slice(line.as_bytes());
            output_batch.push(b'\n');
            if output_batch.len() >= OUTPUT_BATCH_BYTES {
                flush_output_batch(output, &mut output_batch)?;
            }
        }
    }
    if let Some(output) = output.as_ref() {
        flush_output_batch(output, &mut output_batch)?;
    }
    Ok(())
}

fn flush_output_batch(
    output: &Arc<std::sync::Mutex<std::io::BufWriter<std::fs::File>>>,
    batch: &mut Vec<u8>,
) -> MainResult<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut output = output.lock().expect("observer output lock poisoned");
    use std::io::Write;
    output.write_all(batch)?;
    output.flush()?;
    batch.clear();
    Ok(())
}

async fn serve_ui(listener: TcpListener, collector: Arc<ObserverCollector>) -> MainResult<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let collector = Arc::clone(&collector);
        tokio::spawn(async move {
            if let Err(err) = handle_ui_connection(stream, collector).await {
                eprintln!("dashboard connection {peer} failed: {err}");
            }
        });
    }
}

async fn handle_ui_connection(
    mut stream: TcpStream,
    collector: Arc<ObserverCollector>,
) -> MainResult<()> {
    let mut buffer = [0u8; 8192];
    let bytes = stream.read(&mut buffer).await?;
    if bytes == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buffer[..bytes]);
    let Some(request_line) = request.lines().next() else {
        write_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            b"bad request",
        )
        .await?;
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");
    if method != "GET" {
        write_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed",
        )
        .await?;
        return Ok(());
    }

    let path = target.split('?').next().unwrap_or("/");
    match path {
        "/" | "/index.html" => {
            write_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
            )
            .await?;
        }
        "/api/analysis" => {
            let body = serde_json::to_vec(&collector.analysis())?;
            write_response(&mut stream, 200, "OK", "application/json", &body).await?;
        }
        "/api/events" => {
            let limit = query_limit(target).unwrap_or(200).min(2_000);
            let mut events = collector.events();
            if events.len() > limit {
                events = events.split_off(events.len() - limit);
            }
            let body = serde_json::to_vec(&events)?;
            write_response(&mut stream, 200, "OK", "application/json", &body).await?;
        }
        "/healthz" => {
            write_response(&mut stream, 200, "OK", "text/plain; charset=utf-8", b"ok").await?;
        }
        _ => {
            write_response(
                &mut stream,
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                b"not found",
            )
            .await?;
        }
    }
    Ok(())
}

fn query_limit(target: &str) -> Option<usize> {
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "limit")
            .then(|| value.parse::<usize>().ok())
            .flatten()
    })
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> MainResult<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

fn analyze(input: PathBuf) -> MainResult<()> {
    let contents = std::fs::read_to_string(input)?;
    let mut events = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            events.push(serde_json::from_str(trimmed)?);
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&analyze_events(&events))?
    );
    Ok(())
}
