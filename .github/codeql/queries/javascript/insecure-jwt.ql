/**
 * @name Insecure JWT Configuration
 * @description JWT without expiration or weak secret
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision high
 * @id js/insecure-jwt
 * @tags security external/cwe/cwe-327
 */
import javascript

from DataFlow::CallNode jwt
where jwt.getCalleeName() = "sign"
  and jwt.getNumArgument() >= 2
  and not exists(DataFlow::ObjectLiteralNode opts |
    opts = jwt.getArgument(2).getALocalSource() and
    opts.hasPropertyWrite("expiresIn")
  )
select jwt, "JWT token without expiration time"
