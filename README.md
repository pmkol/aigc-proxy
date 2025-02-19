# AIGC Proxy

AIGC Proxy is a lightweight reverse proxy server designed to securely forward requests between clients and an upstream GPT API. It simplifies API communication with minimal configuration.

Join our AIGC community for discussions: [AIGC Zone](https://t.me/aigczone)

## Features

- **Lightweight**: A simple and efficient reverse proxy for forwarding GPT API requests.
- **Client IP Privacy Protection**: Hides client IP addresses by removing `X-Forwarded-For` and `X-Real-IP` headers, ensuring client privacy.
- **Optional `[CONTEXT_ID]` Handling**: Intercepts and manages `[CONTEXT_ID]` tags in requests and responses for applications that require context tracking (optional feature).
- **Authorization Handling**: Validates client requests using a bearer token and forwards authorized requests to the upstream API with the appropriate key.
- **Customizable Logging**: Supports different log levels (`info`, `warn`, `debug`) for detailed monitoring and debugging.

## Usage

### Command-Line Options

| Option   | Description                                                                 | Default Value           |
|----------|-----------------------------------------------------------------------------|-------------------------|
| `-l`     | Listen IP (default: all interfaces)                                        | `""`                    |
| `-p`     | Listen port                                                                | `"2023"`                |
| `-api`   | Upstream API address                                                       | `"https://api.openai.com"` |
| `-key`   | Upstream request key                                                       | `""`                    |
| `-bearer`| Client request key (default: same as `-key`)                               | `""`                    |
| `-nocid` | If set, intercept and remove `[CONTEXT_ID]` (optional)                     | `false`                 |
| `-cache` | Maximum cache size for `[CONTEXT_ID]` handling (optional)                  | `10000`                 |
| `-log`   | Log level: `"info"`, `"warn"`, `"debug"`                                   | `"info"`                |

### Example

Start the proxy server on `0.0.0.0:2023`, forwarding requests to `https://api.openai.com` with the specified keys:

```bash
./aigc-proxy -l 0.0.0.0 -p 2023 -api "https://api.openai.com" -key "your-upstream-key" -bearer "your-client-key" -nocid -cache 10000 -log debug
```

### Logging

The proxy supports different log levels for detailed monitoring:

- **info**: Basic logging of client IPs and authorization details.
- **warn**: Logs warnings and errors.
- **debug**: Detailed logging of request and response details, including headers and body content.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
