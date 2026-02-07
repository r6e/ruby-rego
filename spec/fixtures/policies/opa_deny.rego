package opa

default allow := false

allow if input.method == "GET"

deny[msg] {
  some user in input.users
  user.role == "guest"
  msg := sprintf("guest user: %s", [user.name])
}
