/**
 * @name SQL Injection with Advanced Taint Tracking
 * @description Detects SQL injection across async boundaries and promise chains
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id js/sql-injection-advanced
 * @tags security external/cwe/cwe-089
 */
import javascript
import semmle.javascript.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

class AdvancedSqlInjection extends TaintTracking::Configuration {
  AdvancedSqlInjection() { this = "AdvancedSqlInjection" }
  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource or
    exists(HTTP::RequestInputAccess input | source = input.getAPropertyRead())
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(SQL::SqlString s | s.getAnArgument() = sink.asExpr()) or
    exists(DataFlow::CallNode call | 
      call.getCalleeName().matches("%query%") and 
      sink = call.getAnArgument()
    )
  }
  override predicate isSanitizer(DataFlow::Node node) {
    exists(DataFlow::CallNode sanitize |
      sanitize.getCalleeName().regexpMatch("(escape|sanitize|validate|prepare).*") and
      node = sanitize
    )
  }
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::CallNode promise |
      promise.getCalleeName() = ["then", "catch", "finally"] and
      pred = promise.getAnArgument() and
      succ = promise
    )
  }
}

from AdvancedSqlInjection cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@", source.getNode(), "user input"
