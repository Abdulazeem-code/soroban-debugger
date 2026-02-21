use soroban_debugger::debugger::engine::DebuggerEngine;
use soroban_debugger::runtime::executor::ContractExecutor;
use soroban_debugger::server::debug_server::DebugServer;
use soroban_debugger::client::remote_client::RemoteClient;
use soroban_debugger::protocol::DebugRequest;
use std::fs;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_remote_debug_flow() -> Result<(), Box<dyn std::error::Error>> {
    let wasm_path = "examples/contracts/voting/target/wasm32-unknown-unknown/release/voting_contract.wasm";
    let wasm_bytes = fs::read(wasm_path).expect("Failed to read wasm");
    let executor = ContractExecutor::new(wasm_bytes).expect("Failed to create executor");
    let engine = DebuggerEngine::new(executor, vec![]);
    let token = "test-token".to_string();
    let port = 9999;

    let server = DebugServer::new(engine, token.clone(), None, None).expect("Failed to create server");
    
    let local = tokio::task::LocalSet::new();
    local.run_until(async move {
        tokio::task::spawn_local(async move {
            server.run(port).await.expect("Server failed");
        });

        // Wait for server to start
        sleep(Duration::from_millis(200)).await;

        // Connect client
        let addr = format!("127.0.0.1:{}", port);
        let mut client = RemoteClient::connect(&addr, token, false).await.expect("Client connect failed");

        // Send a request
        let request = DebugRequest::GetState;
        let response = client.send_request(request).await.expect("Request failed");
        println!("Response: {:?}", response);

        // Verify response is State
        match response {
            soroban_debugger::protocol::DebugResponse::State(_) => {},
            _ => panic!("Expected State response, got {:?}", response),
        }
    }).await;

    Ok(())
}
