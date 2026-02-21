use std::collections::HashMap;
use std::fmt;

/// Represents an operator for conditional breakpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Operator::Eq => "==",
            Operator::Ne => "!=",
            Operator::Gt => ">",
            Operator::Lt => "<",
            Operator::Ge => ">=",
            Operator::Le => "<=",
        };
        write!(f, "{}", s)
    }
}

/// Represents a condition for a breakpoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// storage[key] OP value
    Storage {
        key: String,
        operator: Operator,
        value: String,
    },
    /// arg_name OP value
    Argument {
        name: String,
        operator: Operator,
        value: String,
    },
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::Storage { key, operator, value } => {
                write!(f, "storage[{}] {} {}", key, operator, value)
            }
            Condition::Argument { name, operator, value } => {
                write!(f, "{} {} {}", name, operator, value)
            }
        }
    }
}

/// Represents a breakpoint with an optional condition
#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub function: String,
    pub condition: Option<Condition>,
}

impl fmt::Display for Breakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(condition) = &self.condition {
            write!(f, "{} (if {})", self.function, condition)
        } else {
            write!(f, "{}", self.function)
        }
    }
}

/// Manages breakpoints during debugging
pub struct BreakpointManager {
    breakpoints: HashMap<String, Breakpoint>,
}

impl BreakpointManager {
    /// Create a new breakpoint manager
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
        }
    }

    /// Add a breakpoint at a function name with an optional condition
    pub fn add(&mut self, function: &str, condition: Option<Condition>) {
        self.breakpoints.insert(
            function.to_string(),
            Breakpoint {
                function: function.to_string(),
                condition,
            },
        );
    }

    /// Remove a breakpoint
    pub fn remove(&mut self, function: &str) -> bool {
        self.breakpoints.remove(function).is_some()
    }

    /// Check if execution should break at this function, considering conditions
    pub fn should_break(&self, function: &str, storage: &HashMap<String, String>, args_json: Option<&str>) -> bool {
        if let Some(bp) = self.breakpoints.get(function) {
            if let Some(condition) = &bp.condition {
                return self.evaluate_condition(condition, storage, args_json);
            }
            return true;
        }
        false
    }

    fn evaluate_condition(&self, condition: &Condition, storage: &HashMap<String, String>, args_json: Option<&str>) -> bool {
        match condition {
            Condition::Storage { key, operator, value } => {
                if let Some(actual_value) = storage.get(key) {
                    self.compare_values(actual_value, value, *operator)
                } else {
                    false
                }
            }
            Condition::Argument { name, operator, value } => {
                if let Some(args_str) = args_json {
                    // Try to find the argument value in the JSON string
                    // Simple search for now, could be improved with real JSON parsing
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(args_str) {
                        if let Some(actual_val) = v.get(name) {
                            let actual_str = match actual_val {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Number(n) => n.to_string(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                _ => format!("{:?}", actual_val),
                            };
                            return self.compare_values(&actual_str, value, *operator);
                        }
                    }
                }
                false
            }
        }
    }

    fn compare_values(&self, actual: &str, expected: &str, op: Operator) -> bool {
        // Try numeric comparison first
        if let (Ok(a), Ok(e)) = (actual.parse::<i128>(), expected.parse::<i128>()) {
            return match op {
                Operator::Eq => a == e,
                Operator::Ne => a != e,
                Operator::Gt => a > e,
                Operator::Lt => a < e,
                Operator::Ge => a >= e,
                Operator::Le => a <= e,
            };
        }

        // Fallback to string comparison
        match op {
            Operator::Eq => actual == expected,
            Operator::Ne => actual != expected,
            Operator::Gt => actual > expected,
            Operator::Lt => actual < expected,
            Operator::Ge => actual >= expected,
            Operator::Le => actual <= expected,
        }
    }

    /// List all breakpoints
    pub fn list(&self) -> Vec<Breakpoint> {
        self.breakpoints.values().cloned().collect()
    }

    /// Clear all breakpoints
    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }

    /// Check if there are any breakpoints set
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Get count of breakpoints
    pub fn count(&self) -> usize {
        self.breakpoints.len()
    }

    /// Parse a condition string into a Condition object
    pub fn parse_condition(s: &str) -> Result<Condition, String> {
        // storage[key] > value
        if s.starts_with("storage[") {
            let end_bracket = s.find(']').ok_or("Missing closed bracket ']' in storage condition")?;
            let key = s[8..end_bracket].to_string();
            let rem = s[end_bracket+1..].trim();
            
            let (op, val_str) = self::split_op_value(rem)?;
            return Ok(Condition::Storage { key, operator: op, value: val_str });
        }
        
        // name > value
        let (op, _) = self::find_operator(s).ok_or("No operator found (use ==, !=, >, <, >=, <=)")?;
        let op_pos = s.find(op).unwrap();
        let name = s[..op_pos].trim().to_string();
        let val_str = s[op_pos + op.len()..].trim().to_string();
        let operator = match op {
            "==" => Operator::Eq,
            "!=" => Operator::Ne,
            ">=" => Operator::Ge,
            "<=" => Operator::Le,
            ">" => Operator::Gt,
            "<" => Operator::Lt,
            _ => return Err(format!("Unsupported operator: {}", op)),
        };
        
        Ok(Condition::Argument { name, operator, value: val_str })
    }
}

fn find_operator(s: &str) -> Option<(&'static str, usize)> {
    let ops = [">=", "<=", "==", "!=", ">", "<"];
    for op in ops {
        if let Some(pos) = s.find(op) {
            return Some((op, pos));
        }
    }
    None
}

fn split_op_value(s: &str) -> Result<(Operator, String), String> {
    if s.starts_with("==") { Ok((Operator::Eq, s[2..].trim().to_string())) }
    else if s.starts_with("!=") { Ok((Operator::Ne, s[2..].trim().to_string())) }
    else if s.starts_with(">=") { Ok((Operator::Ge, s[2..].trim().to_string())) }
    else if s.starts_with("<=") { Ok((Operator::Le, s[2..].trim().to_string())) }
    else if s.starts_with(">") { Ok((Operator::Gt, s[1..].trim().to_string())) }
    else if s.starts_with("<") { Ok((Operator::Lt, s[1..].trim().to_string())) }
    else { Err(format!("Invalid operator in condition: {}", s)) }
}

impl Default for BreakpointManager {
    fn default() -> Self {
        Self::new()
    }
}
