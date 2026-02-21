use crate::debugger::breakpoint::BreakpointManager;
use crate::debugger::state::DebugState;
use crate::debugger::stepper::Stepper;
use crate::debugger::instruction_pointer::StepMode;
use crate::runtime::executor::ContractExecutor;
use crate::runtime::instrumentation::{Instrumenter, InstructionHook};
use crate::runtime::instruction::Instruction;
use crate::Result;
use tracing::info;
use std::sync::{Arc, Mutex};

/// Core debugging engine that orchestrates execution and debugging
use crate::compare::trace::{ExecutionTrace, BudgetTrace, CallEntry, EventEntry};
use std::collections::BTreeMap;

/// Core debugging engine that orchestrates execution and debugging
/// Core debugging engine that orchestrates execution and debugging.
pub struct DebuggerEngine {
    executor: ContractExecutor,
    breakpoints: BreakpointManager,
    state: Arc<Mutex<DebugState>>,
    timeline: crate::debugger::timeline::TimelineManager,
    stepper: Stepper,
    instrumenter: Instrumenter,
    source_map: crate::debugger::source_map::SourceMap,
    paused: bool,
    last_trace: Option<ExecutionTrace>,
    instruction_debug_enabled: bool,
}

impl DebuggerEngine {
    /// Create a new debugger engine
    pub fn new(executor: ContractExecutor, initial_breakpoints: Vec<String>) -> Self {
        let mut breakpoints = BreakpointManager::new();

        // Add initial breakpoints
        for bp in initial_breakpoints {
            breakpoints.add(&bp);
            info!("Breakpoint set at function: {}", bp);
    /// Create a new debugger engine.
    pub fn new(executor: ContractExecutor, initial_breakpoints: Vec<String>, conditions: Vec<String>) -> Self {
        let mut breakpoints = BreakpointManager::new();

        for (i, bp) in initial_breakpoints.iter().enumerate() {
            let condition = conditions.get(i).and_then(|c| {
                match BreakpointManager::parse_condition(c) {
                    Ok(cond) => Some(cond),
                    Err(e) => {
                        warn!("Invalid condition for breakpoint {}: {}", bp, e);
                        None
                    }
                }
            });
            breakpoints.add(bp, condition);
            if let Some(ref c) = breakpoints.list().last().and_then(|b| b.condition.as_ref()) {
                info!("Conditional breakpoint set at function: {} (if {})", bp, c);
            } else {
                info!("Breakpoint set at function: {}", bp);
            }
        }

        Self {
            executor,
            breakpoints,
            state: Arc::new(Mutex::new(DebugState::new())),
            timeline: crate::debugger::timeline::TimelineManager::new(1000),
            stepper: Stepper::new(),
            instrumenter: Instrumenter::new(),
            source_map: crate::debugger::source_map::SourceMap::new(),
            paused: false,
            last_trace: None,
            instruction_debug_enabled: false,
        }
    }

    /// Enable instruction-level debugging
    pub fn enable_instruction_debug(&mut self, wasm_bytes: &[u8]) -> Result<()> {
        info!("Enabling instruction-level debugging");
        
        // Parse instructions from WASM
        let instructions = self.instrumenter.parse_instructions(wasm_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse instructions: {}", e))?;
        
        let instructions_len = instructions.len();
        
        // Update debug state with instructions
        if let Ok(mut state) = self.state.lock() {
            state.set_instructions(instructions.to_vec());
            state.enable_instruction_debug();
        }
        
        // Enable instrumentation

        // Try to load source map
        if let Err(e) = self.source_map.load(wasm_bytes) {
            info!("No debug info found in WASM: {}", e);
        } else {
            info!("Source map loaded successfully");
        }

        self.instrumenter.enable();
        
        // Set up instruction hook
        let state_ref = Arc::clone(&self.state);
        self.instrumenter.set_hook(move |instruction_index: usize, _instruction: &Instruction| {
            // This callback will be called for each instruction during execution
            if let Ok(mut state) = state_ref.lock() {
                // Advance to the current instruction
                state.advance_to_instruction(instruction_index);
                
                // Check if we should pause
                state.should_pause_execution()
            } else {
                false
            }
        });
        
        self.instruction_debug_enabled = true;
        info!("Instruction-level debugging enabled with {} instructions", instructions_len);
        
        Ok(())
    }

    /// Disable instruction-level debugging
    pub fn disable_instruction_debug(&mut self) {
        info!("Disabling instruction-level debugging");
        
        self.instrumenter.disable();
        self.instrumenter.remove_hook();
        
        if let Ok(mut state) = self.state.lock() {
            state.disable_instruction_debug();
        }
        
        self.instruction_debug_enabled = false;
    }

    /// Check if instruction-level debugging is enabled
    pub fn is_instruction_debug_enabled(&self) -> bool {
        self.instruction_debug_enabled
    }

    /// Execute a contract function with debugging
    /// Execute a contract function with debugging and storage tracking
    pub fn execute(&mut self, function: &str, args: Option<&str>) -> Result<String> {
        info!("Executing function: {}", function);

        // Capture storage state before execution
        let storage_before = self.executor.get_storage_snapshot()?;
        
        // Initialize stack state
        let storage_before_raw = self.executor.get_storage_snapshot()?;
        let mut storage_before = BTreeMap::new();
        for (k, v) in &storage_before_raw {
            storage_before.insert(k.clone(), v.clone());
        if let Ok(mut state) = self.state.lock() {
            state.set_current_function(function.to_string());
            state.call_stack_mut().clear();
            state.call_stack_mut().push(function.to_string(), None);
        }

        // Check if we should break at function entry
        if self.breakpoints.should_break(function) {
        let initial_storage = self.executor.get_storage_snapshot().unwrap_or_default();
        if self.breakpoints.should_break(function, &initial_storage, args) {
            self.pause_at_function(function);
        }

        // Execute the contract
        let start_time = std::time::Instant::now();
        let result = self.executor.execute(function, args);
        let duration = start_time.elapsed();

        // Update call stack from diagnostic events
        // Capture storage state after execution
        let storage_after_raw = self.executor.get_storage_snapshot()?;
        
        let mut storage_after = BTreeMap::new();
        for (k, v) in &storage_after_raw {
            storage_after.insert(k.clone(), v.clone());
        }

        // Capture budget
        let budget_info = crate::inspector::BudgetInspector::get_cpu_usage(self.executor.host());
        let budget_trace = BudgetTrace {
            cpu_instructions: budget_info.cpu_instructions,
            memory_bytes: budget_info.memory_bytes,
            cpu_limit: Some(budget_info.cpu_limit),
            memory_limit: Some(budget_info.memory_limit),
        };

        // Capture events
        let events_raw = self.executor.get_events()?;
        let events = events_raw.iter().map(|e| EventEntry {
            contract_id: e.contract_id.clone(),
            topics: e.topics.clone(),
            data: Some(e.data.clone()),
        }).collect();

        // Assemble call sequence (just the top-level call for now)
        let call_sequence = vec![CallEntry {
            function: function.to_string(),
            args: args.map(|a| a.to_string()),
            depth: 0,
            budget: Some(budget_trace.clone()),
        }];

        // Build the full trace
        let trace = ExecutionTrace {
            version: "1.0".to_string(),
            label: Some(format!("Execution of {}", function)),
            contract: Some(self.executor.contract_address().to_string()),
            function: Some(function.to_string()),
            args: args.map(|a| a.to_string()),
            storage_before,
            storage: storage_after,
            budget: Some(budget_trace),
            return_value: Some(serde_json::Value::String(result.clone())),
            call_sequence,
            events,
        };

        self.last_trace = Some(trace.clone());

        // Calculate and display storage diff if requested via some flag
        let diff = crate::inspector::StorageInspector::compute_diff(&storage_before_raw, &storage_after_raw);
        if !diff.is_empty() {
             crate::inspector::StorageInspector::display_diff(&diff);
        self.update_call_stack(duration)?;

        // If it failed, show the stack
        if let Err(ref e) = result {
            println!("\n[ERROR] Execution failed: {}", e);
            if let Ok(state) = self.state.lock() {
                state.call_stack().display();
            }
        } else if self.is_paused() {
            // If we paused (only at entry for now), show current stack
            if let Ok(state) = self.state.lock() {
                state.call_stack().display();
            }
        }

        result
    }

    /// Update the call stack from diagnostic events
    /// Get the trace from the last execution
    pub fn last_trace(&self) -> Option<&ExecutionTrace> {
        self.last_trace.as_ref()
    }

    /// Step through one instruction
    pub fn step(&mut self) -> Result<()> {
        info!("Stepping...");
        self.paused = false;
        // TODO: Implement actual stepping logic
    fn update_call_stack(&mut self, total_duration: std::time::Duration) -> Result<()> {
        // Get diagnostic events if available
        // Note: get_diagnostic_events may not be implemented yet
        // For now, we'll skip updating from events
        
        if let Ok(mut state) = self.state.lock() {
            let current_func = state.current_function().unwrap_or("entry").to_string();
            let stack = state.call_stack_mut();
            stack.clear();
            // Push the entry function as the root of the stack
            stack.push(current_func, None);
        }

        Ok(())
    }

    /// Step into next instruction
    pub fn step_into(&mut self) -> Result<bool> {
        info!("Step into instruction");
        
        if !self.instruction_debug_enabled {
            return Err(anyhow::anyhow!("Instruction debugging not enabled"));
        }

        let stepped = if let Ok(mut state) = self.state.lock() {
            self.stepper.step_into(&mut state)
        } else {
            false
        };

        if stepped {
            self.record_snapshot();
        }

        self.paused = stepped;
        Ok(stepped)
    }

    /// Step over function calls
    pub fn step_over(&mut self) -> Result<bool> {
        info!("Step over instruction");
        
        if !self.instruction_debug_enabled {
            return Err(anyhow::anyhow!("Instruction debugging not enabled"));
        }

        let stepped = if let Ok(mut state) = self.state.lock() {
            self.stepper.step_over(&mut state)
        } else {
            false
        };

        if stepped {
            self.record_snapshot();
        }

        self.paused = stepped;
        Ok(stepped)
    }

    /// Step out of current function
    pub fn step_out(&mut self) -> Result<bool> {
        info!("Step out of function");
        
        if !self.instruction_debug_enabled {
            return Err(anyhow::anyhow!("Instruction debugging not enabled"));
        }

        let stepped = if let Ok(mut state) = self.state.lock() {
            self.stepper.step_out(&mut state)
        } else {
            false
        };

        if stepped {
            self.record_snapshot();
        }

        self.paused = stepped;
        Ok(stepped)
    }

    /// Step to next basic block
    pub fn step_block(&mut self) -> Result<bool> {
        info!("Step to next basic block");
        
        if !self.instruction_debug_enabled {
            return Err(anyhow::anyhow!("Instruction debugging not enabled"));
        }

        let stepped = if let Ok(mut state) = self.state.lock() {
            self.stepper.step_block(&mut state)
        } else {
            false
        };

        self.paused = stepped;
        Ok(stepped)
    }

    /// Step backwards to previous instruction
    pub fn step_back(&mut self) -> Result<bool> {
        info!("Step back to previous instruction");
        
    /// Step backwards to previous instruction and restore state.
    pub fn step_back(&mut self) -> Result<bool> {
        if let Some(snapshot) = self.timeline.step_back() {
            self.restore_snapshot(snapshot.clone())?;
            self.paused = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Continue execution backwards until next breakpoint or event.
    pub fn continue_back(&mut self) -> Result<()> {
        while let Some(snapshot) = self.timeline.step_back() {
            self.restore_snapshot(snapshot.clone())?;
            
            // Check if we should pause at this point
            // For now, pause at function changes or if we hit the beginning
            let is_beginning = self.timeline.current_pos() == 0;
            if is_beginning || self.breakpoints.should_break(&snapshot.function, &snapshot.storage, None) {
                self.paused = true;
                break;
            }
        }
        Ok(())
    }

    /// Jump to a specific step in the execution history.
    pub fn goto_step(&mut self, step: usize) -> Result<()> {
        if let Some(snapshot) = self.timeline.goto(step) {
            self.restore_snapshot(snapshot.clone())?;
            self.paused = true;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Step {} not found in history", step))
        }
    }

    /// Step by source line.
    pub fn step_source(&mut self) -> Result<bool> {
        if !self.instruction_debug_enabled {
            return Err(anyhow::anyhow!("Instruction debugging not enabled"));
        }

        let stepped = if let Ok(mut state) = self.state.lock() {
            self.stepper.step_back(&mut state)
        } else {
            false
        };
        let start_loc = self.current_source_location();
        let mut stepped = false;

        // Step at least once
        if self.step_into()? {
            stepped = true;
            
            // If we have source info, keep stepping until line changes
            if let Some(start) = start_loc {
                for _ in 0..100 { // Max 100 instructions per source line to avoid infinite loop
                    let current_loc = self.current_source_location();
                    if let Some(current) = current_loc {
                        if current.file != start.file || current.line != start.line {
                            break;
                        }
                    }
                    if !self.step_into()? {
                        break;
                    }
                }
            }
        }

        self.paused = stepped;
        Ok(stepped)
    }

    /// Start instruction stepping with given mode
    fn record_snapshot(&mut self) {
        let snapshot = {
            let state = self.state.lock().unwrap();
            let host = self.executor.host();
            let budget = crate::inspector::BudgetInspector::get_cpu_usage(host);
            let events = self.executor.get_events().unwrap_or_default();

            crate::debugger::timeline::ExecutionSnapshot {
                step: state.step_count(),
                instruction_index: state.instruction_pointer().current_index(),
                function: state.current_function().unwrap_or("unknown").to_string(),
                call_stack: state.call_stack().get_stack().to_vec(),
                storage: self.executor.get_storage_snapshot().unwrap_or_default(),
                budget,
                events_count: events.len(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            }
        };
        
        self.timeline.push(snapshot);
    }

    fn restore_snapshot(&mut self, snapshot: crate::debugger::timeline::ExecutionSnapshot) -> Result<()> {
        // Restore engine state
        if let Ok(mut state) = self.state.lock() {
            state.advance_to_instruction(snapshot.instruction_index);
            state.set_current_function(snapshot.function, None);
            
            let stack = state.call_stack_mut();
            stack.clear();
            for frame in snapshot.call_stack {
                stack.push_frame(frame);
            }
        }

        // Restore executor state (storage)
        let storage_json = serde_json::to_string(&snapshot.storage)?;
        self.executor.set_initial_storage(storage_json)?;

        Ok(())
    }

    /// Get the execution timeline.
    pub fn get_timeline(&self) -> &crate::debugger::timeline::TimelineManager {
        &self.timeline
    }

    /// Start instruction stepping with given mode.
    pub fn start_instruction_stepping(&mut self, mode: StepMode) -> Result<()> {
        if !self.instruction_debug_enabled {
            return Err(anyhow::anyhow!("Instruction debugging not enabled"));
        }

        if let Ok(mut state) = self.state.lock() {
            self.stepper.start(mode, &mut state);
            self.paused = true;
        }

        Ok(())
    }

    /// Continue execution until next breakpoint
    pub fn continue_execution(&mut self) -> Result<()> {
        info!("Continuing execution...");
        self.paused = false;
        
        if let Ok(mut state) = self.state.lock() {
            self.stepper.continue_execution(&mut state);
        }
        
        Ok(())
    }

    /// Pause execution at a function
    fn pause_at_function(&mut self, function: &str) {
        crate::logging::log_breakpoint(function);
        self.paused = true;
        
        if let Ok(mut state) = self.state.lock() {
            state.set_current_function(function.to_string());
            state.call_stack().display();
        }
    }

    /// Check if debugger is currently paused
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Get current debug state
    pub fn state(&self) -> Arc<Mutex<DebugState>> {
        Arc::clone(&self.state)
    }

    /// Get current instruction
    /// Get current source location for the current instruction.
    pub fn current_source_location(&self) -> Option<crate::debugger::source_map::SourceLocation> {
        let state = self.state.lock().ok()?;
        let instruction = state.current_instruction()?;
        self.source_map.lookup(instruction.offset)
    }

    pub fn source_map(&self) -> &crate::debugger::source_map::SourceMap {
        &self.source_map
    }

    pub fn source_map_mut(&mut self) -> &mut crate::debugger::source_map::SourceMap {
        &mut self.source_map
    }

    pub fn current_instruction(&self) -> Option<Instruction> {
        if let Ok(state) = self.state.lock() {
            state.current_instruction().cloned()
        } else {
            None
        }
    }

    /// Get instruction context for display
    pub fn get_instruction_context(&self, context_size: usize) -> Vec<(usize, Instruction, bool)> {
        if let Ok(state) = self.state.lock() {
            state.get_instruction_context(context_size)
                .into_iter()
                .map(|(idx, inst, current)| (idx, inst.clone(), current))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get mutable reference to breakpoint manager
    pub fn breakpoints_mut(&mut self) -> &mut BreakpointManager {
        &mut self.breakpoints
    }

    /// Get reference to executor
    pub fn executor(&self) -> &ContractExecutor {
        &self.executor
    }

    /// Compatibility method for old step interface
    pub fn step(&mut self) -> Result<()> {
        let _ = self.step_into()?;
        if self.instruction_debug_enabled {
            let _ = self.step_into()?;
        }
        if let Ok(mut state) = self.state.lock() {
            state.increment_step();
        }
        self.record_snapshot();
        Ok(())
    }
    
    /// Get mutable reference to executor
    pub fn executor_mut(&mut self) -> &mut ContractExecutor {
        &mut self.executor
    }
}
