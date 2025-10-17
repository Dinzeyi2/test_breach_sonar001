/**
 * @name Authentication Bypass Detection
 * @description Detects routes without proper auth checks
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id js/auth-bypass-advanced
 * @tags security external/cwe/cwe-306
 */
import javascript

predicate isAuthMiddleware(DataFlow::Node node) {
  exists(string name | name = node.asExpr().(Identifier).getName() |
    name.regexpMatch(".*(auth|Auth|jwt|JWT|token|Token|guard|Guard|protect|Protect).*")
  )
}

predicate hasAuthCheck(Express::RouteHandler handler) {
  exists(DataFlow::CallNode auth |
    isAuthMiddleware(auth.getCallee()) and
    auth.flowsTo(handler.getAParameter())
  ) or
  exists(IfStmt check |
    check.getCondition().toString().regexpMatch(".*(auth|session|token|user).*") and
    check.getEnclosingFunction() = handler.getFunction()
  )
}

from Express::RouteHandler handler, Express::RouteSetup setup
where setup.getARouteHandler() = handler
  and not hasAuthCheck(handler)
  and setup.getRelativePath() != ["/login", "/register", "/public", "/health"]
select handler, "Route without authentication: " + setup.getRelativePath()
