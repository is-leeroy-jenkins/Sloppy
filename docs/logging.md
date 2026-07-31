# Logging

## :material-database-alert-outline: Storage

Structured exceptions are written to the SQLite database configured by `config.LOG_PATH`. The default path is:

```text
logging/Exceptions.db
```

## :material-alert-decagram-outline: Error Metadata

Each logged error records application context through fields such as:

- Module.
- Cause or component.
- Method signature.
- Sanitized message.
- Sanitized traceback.
- Timestamp and database identifier managed by the logger.

## :material-code-braces: Standard Pattern

```python
except Error:
    raise
except Exception as e:
    exception = Error( e )
    exception.module = 'app'
    exception.cause = 'ComponentName'
    exception.method = 'method_name( argument: type ) -> return_type'
    Logger( ).write( exception )
    raise exception
```

`except Error: raise` prevents a wrapped exception from being logged again at every call boundary.

## :material-access-point-minus: Background Capture Pattern

Capture-thread failures cannot be raised directly through the Streamlit execution thread. The background path:

1. Wraps and logs the exception.
2. Sanitizes the user-facing error text.
3. Places the message in the capture-error queue.
4. Signals capture termination when required.
5. Returns control to the thread boundary.

## :material-shield-check-outline: Sanitization

`boogr.py` limits stored message and traceback lengths and can suppress sensitive path or text details according to configuration. Logging should not store raw packet payloads, credentials, or unrelated user data.

## :material-calendar-remove-outline: Retention

Retention behavior is controlled through logging configuration. Database cleanup removes records older than the configured retention period when retention is enabled.
