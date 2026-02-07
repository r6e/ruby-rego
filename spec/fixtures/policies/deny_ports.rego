package compliance

deny[msg] {
  some port in input.open_ports
  port == 22
  msg := "port 22 should not be exposed"
}
