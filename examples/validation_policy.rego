package validation

deny[msg] {
  input.enabled == false
  msg := "feature must be enabled"
}

deny[msg] {
  input.timeout < 30
  msg := "timeout must be at least 30"
}
