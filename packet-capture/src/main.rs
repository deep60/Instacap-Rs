use clap::Parser;
use log::info;
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;

mod packet_capture;
mod protocol_parser;
mod deep_inspection;
mod performance_metrics;

use packet_capture::PacketCapture;
use protocol_parser::ProtocolParser;
use deep_inspection::DeepInspection;
use performance_metrics::PerformanceMetrics;

#[derive(Parser)]
#[command(name = "packet-analyzer")]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(short, long, default_value = "1024")]
    buffer_size: usize,

    #[arg(short, long)]
    promiscuous: bool,

    #[arg(short, long)]
    deep_inspection: bool,

    #[arg(short, long, default_value = "")]
    filter: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting Packet Analyzer on interface: {}", args.interface);

    // Create communincation channels
    let (packet_tx, packet_rx) = mpsc::channel(10000);
    let (analysis_tx, _analysis_rx) = mpsc::channel(5000);
    let (alert_tx, _alert_rx) = mpsc::channel(1000);
    let (perf_tx, mut perf_rx) = mpsc::channel(1000);

    // Initialize components
    let capture_config = packet_capture::CaptureConfig { 
        interface: args.interface.clone(),
        buffer_size: args.buffer_size,
        promiscuous: args.promiscuous,
        filter: args.filter,
        deep_inspection: args.deep_inspection,
    };

    // Start packet capture
    let capturer = Arc::new(packet_capture::PacketCapturer::new(capture_config)?);
    let capturer_clone = capturer.clone();
    
    if args.deep_inspection {
        // For deep inspection, send packets directly to inspector
        let (direct_packet_tx, direct_packet_rx) = mpsc::channel(10000);
        
        tokio::spawn(async move {
            capturer_clone.start_capture(direct_packet_tx).await
        });
        
        // Start deep packet inspection
        let inspector: Arc<deep_inspection::DeepInspector> = Arc::new(deep_inspection::DeepInspector::new().await?);
        let inspector_clone = inspector.clone();
        tokio::spawn(async move {
            inspector_clone.inspect_stream(direct_packet_rx, alert_tx, perf_tx).await 
        });
    } else {
        // For normal analysis, use protocol parser
        tokio::spawn(async move {
            capturer_clone.start_capture(packet_tx).await
        });
        
        // Start protocol analysis
        let mut analyzer = protocol_parser::ProtocolParser::new();
        tokio::spawn(async move {
            analyzer.analyze_stream(packet_rx, analysis_tx).await
        });
    }

    // Start performance monitoring 
    let _perf_monitor = Arc::new(performance_metrics::PerformanceTracker::new(1000, std::time::Duration::from_secs(1)));
    tokio::spawn(async move {
        // Assume monitor_performance is a function that processes perf_rx,
        let _ = perf_rx.recv().await; // placeholder
    });

    // Keep running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down packet analyzer");

    Ok(())
}
