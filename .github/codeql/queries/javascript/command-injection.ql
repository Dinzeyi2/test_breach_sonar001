/**
 * @name Command Injection
 * @description User input flows to system command execution
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.5
 * @precision high
 * @id js/command-injection-advanced
 * @tags security external/cwe/cwe-078
 */
import javascript
import semmle.javascript.security.dataflow.CommandInjectionQuery
import DataFlow::PathGraph

class AdvancedCommandInjection extends TaintTracking::Configuration {
  AdvancedCommandInjection() { this = "AdvancedCommandInjection" }
  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(SystemCommandExecution exec | sink = exec.getACommandArgument())
  }
}

from AdvancedCommandInjection cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Command injection from $@", source.getNode(), "user input"
