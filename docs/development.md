# Development Guide

**Last Updated: December 31, 2025**

This guide provides instructions for setting up a development environment, running tests, and contributing to the Akita Meshtastic Meshcore Bridge (AMMB) project.

## Setting Up Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AkitaEngineering/akita-meshtastic-meshcore-bridge.git
   cd akita-meshtastic-meshcore-bridge
   ```

2. **Create and activate a Python virtual environment:**
   ```bash
   python -m venv venv
   # On Windows: .\venv\Scripts\activate
   # On Linux/macOS: source venv/bin/activate
   ```
   Using a virtual environment isolates project dependencies.

3. **Install runtime and development dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
   This installs runtime dependencies (`meshtastic`, `pyserial`, `pypubsub`, `paho-mqtt`) and development tools (`pytest`, `pytest-cov`, `flake8`, `mypy`).

## Project Structure

```
akita-meshtastic-meshcore-bridge/
├── ammb/                    # Main package
│   ├── __init__.py
│   ├── bridge.py           # Bridge orchestrator
│   ├── config_handler.py   # Configuration management
│   ├── meshtastic_handler.py # Meshtastic network handler
│   ├── meshcore_handler.py  # Serial handler
│   ├── mqtt_handler.py      # MQTT handler
│   ├── protocol.py          # Serial protocol handlers
│   ├── utils.py             # Utility functions
│   ├── metrics.py           # Metrics collection
│   ├── health.py            # Health monitoring
│   ├── api.py               # REST API server
│   ├── validator.py         # Message validation
│   ├── rate_limiter.py      # Rate limiting
│   └── message_logger.py    # Message persistence
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_config_handler.py
│   └── test_protocol.py
├── docs/                    # Documentation
│   ├── architecture.md
│   ├── configuration.md
│   ├── development.md
│   └── usage.md
├── examples/                # Example files
│   ├── config.ini.example
│   └── meshcore_simulator.py
├── run_bridge.py           # Main entry point
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt   # Development dependencies
└── README.md              # Project overview
```

## Running Tests

The project uses `pytest` for automated testing.

1. **Ensure your virtual environment is active.**

2. **Navigate to the project root directory.**

3. **Run all tests:**
   ```bash
   pytest
   ```
   This will discover and run all tests located in the `tests/` directory.

4. **Run tests with coverage report:**
   ```bash
   pytest --cov=ammb --cov-report term-missing
   ```
   This runs the tests and generates a report showing which lines of the source code in the `ammb/` directory were executed by the tests.

5. **Run specific test file:**
   ```bash
   pytest tests/test_protocol.py
   ```

6. **Run with verbose output:**
   ```bash
   pytest -v
   ```

## Code Style and Linting

We use `flake8` for checking code style against PEP 8 guidelines and common errors.

1. **Ensure your virtual environment is active.**

2. **Navigate to the project root directory.**

3. **Run flake8:**
   ```bash
   flake8 ammb/ tests/ run_bridge.py
   ```
   This will report any style violations or potential errors. Aim for zero reported issues.

4. **Check specific file:**
   ```bash
   flake8 ammb/bridge.py
   ```

### Project linting policy ✅

- **Max line length:** 79 characters (flake8 E501). When long lines are found, prefer **targeted wrapping or splitting** (for example: split long strings, break complex expressions, or use short helper variables) rather than increasing the line length limit.
- **Third-party packages:** Do **not** edit files under `.venv` or other external package directories to satisfy linter rules. Instead, exclude those directories from lint runs (we include `.venv` in the project's `.flake8` file).
- **Logging:** Prefer parameterized logging calls (e.g., `logger.info("Connected to %s", port)`) instead of long f-strings to keep messages shorter and avoid unnecessary formatting overhead.
- **Fix process:** When addressing E501 issues in project files, make conservative, behavior-preserving edits (wrap strings, reflow docstrings, or adjust logging). Re-run tests and `mypy` after each change to ensure no regressions.

Example: In this revision we fixed several E501 cases in `ammb/` and `examples/` by wrapping long strings and using parameterized logging; tests and `mypy` were re-run to confirm the project remains correct.

## Static Type Checking

We use `mypy` for static type checking to catch potential type-related errors before runtime.

1. **Ensure your virtual environment is active.**

2. **Navigate to the project root directory.**

3. **Run mypy:**
   ```bash
   mypy ammb/ run_bridge.py
   ```
   This will analyze the type hints in the code and report any inconsistencies or errors. Aim for zero reported issues.

4. **Check specific module:**
   ```bash
   mypy ammb/bridge.py
   ```

## Code Quality Standards

### Type Hints

All function signatures should include type hints:

```python
def process_message(message: Dict[str, Any]) -> bool:
    """Process a message and return success status."""
    ...
```

### Documentation Strings

All public functions and classes should have docstrings:

```python
class MessageHandler:
    """Handles message processing and validation."""
    
    def validate(self, data: str) -> bool:
        """
        Validate message data.
        
        Args:
            data: Message data to validate
            
        Returns:
            True if valid, False otherwise
        """
        ...
```

### Error Handling

Use appropriate exception handling:

```python
try:
    result = risky_operation()
except SpecificException as e:
    logger.error(f"Operation failed: {e}", exc_info=True)
    return None
```

### Thread Safety

All shared data structures must use locks:

```python
class ThreadSafeCounter:
    def __init__(self):
        self._count = 0
        self._lock = threading.Lock()
    
    def increment(self):
        with self._lock:
            self._count += 1
```

## Contribution Guidelines

We welcome contributions! Please follow these steps:

1. **Fork the repository** on GitHub.

2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_FORK_USERNAME/akita-meshtastic-meshcore-bridge.git
   ```

3. **Create a new branch** for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

4. **Set up your development environment** as described above.

5. **Make your changes.** Ensure you:
   * Follow the existing code style
   * Add type hints to all functions
   * Write docstrings for public APIs
   * Add tests for new features or bug fixes
   * Update documentation if necessary
   * Ensure all tests pass (`pytest`)
   * Ensure linters pass (`flake8 ammb/ tests/ run_bridge.py`)
   * Ensure type checks pass (`mypy ammb/ run_bridge.py`)

6. **Commit your changes** with clear and descriptive commit messages:
   ```bash
   git commit -m "Add feature: description of what was added"
   git commit -m "Fix bug: description of what was fixed"
   ```

7. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

8. **Open a Pull Request (PR)** from your fork's branch to the `main` branch of the original repository.

9. **Clearly describe** the changes made in the PR description and link to any relevant issues.

10. **Respond to feedback** or requested changes during the code review process.

## Adding New Features

### Adding New Serial Protocols

To support a different serial protocol:

1. Create a new class in `ammb/protocol.py` that inherits from `MeshcoreProtocolHandler`.

2. Implement the required methods:
   ```python
   class YourProtocol(MeshcoreProtocolHandler):
       def read(self, serial_port) -> Optional[bytes]:
           """Read data from serial port."""
           ...
       
       def encode(self, data: Dict[str, Any]) -> Optional[bytes]:
           """Encode dictionary to bytes."""
           ...
       
       def decode(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
           """Decode bytes to dictionary."""
           ...
   ```

3. Update the `get_serial_protocol_handler()` factory function in `ammb/protocol.py`:
   ```python
   _serial_protocol_handlers = {
       'json_newline': JsonNewlineProtocol,
       'raw_serial': RawSerialProtocol,
       'your_protocol': YourProtocol,  # Add here
   }
   ```

4. Add the new protocol name as an option for the `SERIAL_PROTOCOL` setting in:
   * `docs/configuration.md`
   * `examples/config.ini.example`

5. Add tests for your new protocol handler in `tests/test_protocol.py`.

### Adding New External Transports

To add a new external transport (e.g., HTTP, WebSocket):

1. Create a new handler class similar to `MeshcoreHandler` or `MQTTHandler`:
   ```python
   class YourTransportHandler:
       def __init__(self, config, to_meshtastic_queue, from_meshtastic_queue, shutdown_event):
           # Initialize with metrics, health, validator, rate_limiter
           ...
       
       def connect(self) -> bool:
           # Implement connection logic
           ...
       
       def start_publisher(self):
           # Start background threads if needed
           ...
       
       def stop(self):
           # Clean shutdown
           ...
   ```

2. Integrate with existing systems:
   * Use `get_metrics()` for metrics collection
   * Use `get_health_monitor()` for health tracking
   * Use `MessageValidator` for validation
   * Use `RateLimiter` for rate limiting

3. Add to `Bridge` class initialization in `ammb/bridge.py`.

4. Update configuration handler to support new transport settings.

5. Add tests for the new transport handler.

### Adding New API Endpoints

To add new REST API endpoints:

1. Add handler method in `BridgeAPIHandler` class in `ammb/api.py`:
   ```python
   def _handle_your_endpoint(self):
       """Handle your new endpoint."""
       data = {"your": "data"}
       self._send_response(200, data)
   ```

2. Add route in `do_GET()` or `do_POST()` method:
   ```python
   elif path == '/api/your_endpoint':
       self._handle_your_endpoint()
   ```

3. Update API documentation in `docs/usage.md`.

## Testing Guidelines

### Unit Tests

Write unit tests for individual functions and classes:

```python
def test_message_validation():
    validator = MessageValidator()
    valid_msg = {"destination": "^all", "text": "Hello"}
    is_valid, error = validator.validate_meshtastic_message(valid_msg)
    assert is_valid
    assert error is None
```

### Integration Tests

Write integration tests for component interactions:

```python
def test_bridge_initialization():
    config = load_config("test_config.ini")
    bridge = Bridge(config)
    assert bridge.meshtastic_handler is not None
    assert bridge.external_handler is not None
```

### Test Fixtures

Use pytest fixtures for common test setup:

```python
@pytest.fixture
def test_config(tmp_path):
    config_path = tmp_path / "config.ini"
    # Create test configuration
    return config_path
```

## Debugging

### Enable Debug Logging

Set `LOG_LEVEL = DEBUG` in `config.ini` for detailed logging.

### Use Python Debugger

Add breakpoints in code:
```python
import pdb; pdb.set_trace()
```

Or use IDE debugger with breakpoints.

### Check Metrics

Use the REST API to check metrics:
```bash
curl http://localhost:8080/api/metrics
```

### Check Health Status

Use the REST API to check health:
```bash
curl http://localhost:8080/api/health
```

## Release Process

When preparing a release:

1. Update version in `ammb/__init__.py`
2. Update `CHANGELOG.md` with release notes
3. Update documentation dates
4. Run full test suite
5. Run linters and type checkers
6. Create git tag
7. Push to repository

## Getting Help

If you need help with development:

1. Check existing documentation
2. Review code comments
3. Check test examples
4. Open an issue on GitHub
5. Contact maintainers
