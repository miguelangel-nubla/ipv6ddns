# Sentinel Journal 🛡️

## 2025-05-14 - Web server lacks timeouts and uses default mux
**Vulnerability:** The optional web server in `cmd/ipv6ddns/ipv6ddns.go` used `http.ListenAndServe` with the default global `http.DefaultServeMux` and no timeouts. This exposed the application to potential Denial of Service (DoS) attacks like Slowloris and other resource exhaustion risks.
**Learning:** Default Go HTTP settings are often insufficient for production-grade security. `http.DefaultServeMux` is a global variable that any package can modify, which can lead to unintended exposure of endpoints.
**Prevention:** Always use a custom `http.ServeMux` and a configured `http.Server` with explicit timeouts and method/path validation.
