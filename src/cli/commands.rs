use crate::cli::args::{InspectArgs, InteractiveArgs, RunArgs};
use crate::debugger::engine::DebuggerEngine;
use crate::runtime::executor::ContractExecutor;
use crate::ui::tui::DebuggerUI;
use crate::Result;
use anyhow::Context;
use std::fs;

/// Execute the run command
pub fn run(args: RunArgs) -> Result<()> {
    println!("Loading contract: {:?}", args.contract);

    // Load WASM file
    let wasm_bytes = fs::read(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    println!("Contract loaded successfully ({} bytes)", wasm_bytes.len());

    // Parse arguments if provided
    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    // Parse storage if provided
    let initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    println!("\nStarting debugger...");
    println!("Function: {}", args.function);
    if let Some(ref args) = parsed_args {
        println!("Arguments: {}", args);
    }

    // Create executor
    let mut executor = ContractExecutor::new(wasm_bytes)?;

    // Set up initial storage if provided
    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }

    // Create debugger engine
    let mut engine = DebuggerEngine::new(executor, args.breakpoint);

    if args.server {
        let token = args.token.clone().ok_or_else(|| anyhow::anyhow!("Token required for server mode"))?;
        let server = crate::server::debug_server::DebugServer::new(
            engine, 
            token, 
            args.tls_cert.as_deref(), 
            args.tls_key.as_deref()
        )?;
        
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(server.run(args.port))?;
        return Ok(());
    }

    if let Some(remote_addr) = args.remote {
        let token = args.token.clone().ok_or_else(|| anyhow::anyhow!("Token required for remote mode"))?;
        let rt = tokio::runtime::Runtime::new()?;
        // Use TLS if either cert or key is provided, or if we want to default to TLS if available.
        // For client-side, we might just want a flag --use-tls.
        // Let's assume for now if they provide ANY tls arg or if we want to detect it.
        let use_tls = args.tls_cert.is_some() || args.tls_key.is_some();
        let mut client = rt.block_on(crate::client::remote_client::RemoteClient::connect(&remote_addr, token, use_tls))?;
        
        println!("\nConnected to remote debugger.");
        let request = crate::protocol::DebugRequest::Execute {
            function: args.function.clone(),
            args: args.args.clone(),
        };
        
        let response = rt.block_on(client.send_request(request))?;
        println!("Remote Response: {:?}", response);
        return Ok(());
    }

    // Execute locally with debugging
    println!("\n--- Execution Start ---\n");
    let result = engine.execute(&args.function, parsed_args.as_deref())?;
    println!("\n--- Execution Complete ---\n");

    println!("Result: {:?}", result);

    Ok(())
}

/// Execute the interactive command
pub fn interactive(args: InteractiveArgs) -> Result<()> {
    println!("Starting interactive debugger for: {:?}", args.contract);

    // Load WASM file
    let wasm_bytes = fs::read(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    println!("Contract loaded successfully ({} bytes)", wasm_bytes.len());

    // Create executor
    let executor = ContractExecutor::new(wasm_bytes)?;

    // Create debugger engine
    let engine = DebuggerEngine::new(executor, vec![]);

    // Start interactive UI
    println!("\nStarting interactive mode...");
    println!("Type 'help' for available commands\n");

    let mut ui = DebuggerUI::new(engine)?;
    ui.run()?;

    Ok(())
}

/// Execute the inspect command
pub fn inspect(args: InspectArgs) -> Result<()> {
    println!("Inspecting contract: {:?}", args.contract);

    // Load WASM file
    let wasm_bytes = fs::read(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    println!("\nContract Information:");
    println!("  Size: {} bytes", wasm_bytes.len());

    if args.functions {
        println!("\nExported Functions:");
        let functions = crate::utils::wasm::parse_functions(&wasm_bytes)?;
        for func in functions {
            println!("  - {}", func);
        }
    }

    if args.metadata {
        println!("\nMetadata:");
        println!("  (Metadata parsing not yet implemented)");
    }

    Ok(())
}

/// Parse JSON arguments into a string for now (will be improved later)
fn parse_args(json: &str) -> Result<String> {
    // Basic validation
    serde_json::from_str::<serde_json::Value>(json)
        .with_context(|| format!("Invalid JSON arguments: {}", json))?;
    Ok(json.to_string())
}

/// Parse JSON storage into a string for now (will be improved later)
fn parse_storage(json: &str) -> Result<String> {
    // Basic validation
    serde_json::from_str::<serde_json::Value>(json)
        .with_context(|| format!("Invalid JSON storage: {}", json))?;
    Ok(json.to_string())
}