use clap::Parser;
use log::info;
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;

#[derive(Parser)]
#[command(name = "packet-analyzer")]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(short, long, default_value = "1024")]
    buffer_size: usize,

    #[arg(short, long)]
    promiscuous: bool,

    #[arg(short, long, default_value = "")]
    deep_inspection: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting Packet Analyzer on interface: {}", args.interface);

    // Create communincation channels
    let (packet_tx, packet_rx) = mpsc::channel(10000);
    let (analysis_tx, analysis_rx) = mpsc::channel(5000);
    let (alert_tx, alert_rx) = mpsc::channel(1000);
    let (perf_tx, perf_rx) = mpsc::channel(1000);

    // Initialize components
    let capture_config = pcap::CaptureConfig { 
        interface: args.interface.clone(),
        buffer_size: args.buffer_size,
        promiscuous: args.promiscuous,
        filter: args.filter,
        deep_inspection: args.deep_inspection,
    };

    // Start packet capture
    let capturer = Arc::new(packet_capture::PacketCapturer::new(capture_config)?);
    let capturer_clone = capturer.clone();
    tokio::spawn(async move {
        capturer_clone.start_capture(packet_tx).await
    });

    // Start protocol analysis
    let analyzer = Arc::new(protocol_parser::ProtocolAnalyzer::new());
    let analyzer_clone = analyzer.clone();
    tokio::spawn(async move {
        analyzer_clone.analyze_stram(packet_rx, analysis_tx).await
    });

    // Start deep packet inspection(if enabled)
    if args.deep_inspection {
        let inspector = Arc::new(deep_inspection::DeepInspector::new().await?);
        let inspector_clone = inspector.clone();
        tokio::spawn(async move {
            inspector_clone.inspect_stream(analysis_rx, alert_tx, perf_tx).await 
        });
    }

    // Start performance monitoring 
    let perf_monitor = Arc::new(performance_metrics::PerformanceMonitor::new());
    let perf_clone = perf_monitor.clone();
    tokio::spawn(async move {
        perf_clone.monitor_performance(perf_rx).await
    });

    // Keep running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down packet analyzer");

    Ok(())
}
