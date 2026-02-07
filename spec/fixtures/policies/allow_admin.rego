package auth

default allow := false

allow {
  input.user == "admin"
}
