package httpapi

default allow := false

allow if input.method == "GET"
allow if input.method == "HEAD"
