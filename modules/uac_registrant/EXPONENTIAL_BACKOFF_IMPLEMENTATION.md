# Exponential Backoff and Rate Limiting Implementation for uac_registrant Module

## Overview
This implementation adds exponential backoff retry logic and rate limiting to the uac_registrant module to improve reliability, reduce server load during registration failures, and prevent system overload during startup.

## Changes Made

### 1. Configuration Parameters
Added six new module parameters:

#### Exponential Backoff Parameters:
- `retry_base_delay` (default: 5 seconds) - Initial retry delay
- `retry_max_delay` (default: 300 seconds) - Maximum retry delay
- `retry_max_attempts` (default: 5) - Maximum number of retry attempts
- `retry_backoff_multiplier` (default: 2) - Multiplier for exponential backoff

#### Rate Limiting Parameters:
- `reg_rate_limit_per_sec` (default: 10) - Maximum initial registrations per second
- `reg_re_reg_limit_per_sec` (default: 50) - Maximum re-registrations per second

### 2. Data Structure Updates
Extended `reg_record_t` structure with:
- `failed_attempts` - Counter for failed attempts since last reload
- `next_retry_time` - Timestamp when next retry should occur
- `current_retry_delay` - Current calculated retry delay in seconds

### 3. Core Functions
- `calculate_exponential_backoff_delay()` - Calculates delay using formula: base_delay * (multiplier ^ attempt)
- `apply_jitter()` - Adds random jitter (up to 25%) to prevent thundering herd

### 4. Retry Logic Updates
Modified `run_timer_check()` function to:
- Check if retry time has arrived before attempting retry
- Calculate exponential backoff delay for each retry attempt
- Reset retry state on successful registration
- Preserve retry state during module reload

### 5. Rate Limiting Logic
Added rate limiting in `NOT_REGISTERED_STATE` case to:
- Control initial registrations during startup
- Control re-registrations separately
- Disable rate limiting when set to 0
- Provide independent counters for each type

## Retry Behavior

### Delay Progression
- Attempt 1: 5 seconds (base delay)
- Attempt 2: 10 seconds (5 * 2^1)
- Attempt 3: 20 seconds (5 * 2^2)
- Attempt 4: 40 seconds (5 * 2^3)
- Attempt 5: 80 seconds (5 * 2^4)
- Attempt 6+: 300 seconds (capped at max_delay)

### Jitter
Each calculated delay has up to 25% random jitter added to prevent multiple registrants from retrying simultaneously.

### State Management
- Retry state is preserved during module reload
- Retry state is reset on successful registration
- Failed attempts counter is incremented on each retry

## Rate Limiting Behavior

### Initial Registrations
- Controlled by `reg_rate_limit_per_sec` parameter
- Prevents system overload during startup
- Records exceeding limit are skipped for that timer cycle
- Automatically retried in next timer cycle (100ms later)

### Re-registrations
- Controlled by `reg_re_reg_limit_per_sec` parameter
- Separate from initial registration rate limiting
- Allows higher rates for predictable re-registrations
- Independent counter and limit

### Disable Feature
- Set parameter to 0 to disable rate limiting for that type
- No performance overhead when disabled
- Clear logging indicates when rate limiting is disabled

## Configuration Examples

### Basic Exponential Backoff
```
modparam("uac_registrant", "retry_base_delay", 10)
modparam("uac_registrant", "retry_max_delay", 600)
modparam("uac_registrant", "retry_max_attempts", 15)
modparam("uac_registrant", "retry_backoff_multiplier", 2)
```

### Rate Limiting Only
```
modparam("uac_registrant", "reg_rate_limit_per_sec", 5)      # 5 initial registrations/sec
modparam("uac_registrant", "reg_re_reg_limit_per_sec", 100)   # 100 re-registrations/sec
```

### Disable Rate Limiting
```
modparam("uac_registrant", "reg_rate_limit_per_sec", 0)      # Disable initial rate limiting
modparam("uac_registrant", "reg_re_reg_limit_per_sec", 0)    # Disable re-registration rate limiting
```

### Complete Configuration
```
# Exponential backoff settings
modparam("uac_registrant", "retry_base_delay", 5)
modparam("uac_registrant", "retry_max_delay", 300)
modparam("uac_registrant", "retry_max_attempts", 5)
modparam("uac_registrant", "retry_backoff_multiplier", 2)

# Rate limiting settings
modparam("uac_registrant", "reg_rate_limit_per_sec", 10)     # Startup protection
modparam("uac_registrant", "reg_re_reg_limit_per_sec", 50)   # Re-registration control
```

## Benefits

### Exponential Backoff Benefits:
1. **Reduced Server Load**: Longer delays between retries reduce server stress
2. **Better Reliability**: Exponential backoff handles temporary failures gracefully
3. **Thundering Herd Prevention**: Jitter prevents synchronized retries
4. **Configurable**: All parameters can be tuned for specific environments
5. **Backward Compatible**: Existing functionality is preserved

### Rate Limiting Benefits:
1. **Startup Protection**: Prevents system overload during service startup
2. **Independent Control**: Separate limits for initial vs re-registrations
3. **Flexible Configuration**: Can disable rate limiting entirely if needed
4. **Performance**: No overhead when rate limiting is disabled
5. **Debug Visibility**: Clear logging shows rate limiting status

## Debug Information
Enhanced debug logging includes:

### Exponential Backoff:
- Retry attempt number
- Calculated delay
- Next retry timestamp
- Current retry delay

### Rate Limiting:
- Current rate count vs limit
- Registration type (initial vs re-registration)
- Rate limiting status (enabled/disabled)
- Skipped records due to rate limiting

## Use Cases

### High-Volume Startup
```
modparam("uac_registrant", "reg_rate_limit_per_sec", 5)      # Slow startup
modparam("uac_registrant", "reg_re_reg_limit_per_sec", 200)  # Fast re-registrations
```

### Development/Testing
```
modparam("uac_registrant", "reg_rate_limit_per_sec", 0)      # No rate limiting
modparam("uac_registrant", "reg_re_reg_limit_per_sec", 0)    # No rate limiting
```

### Production Environment
```
modparam("uac_registrant", "reg_rate_limit_per_sec", 10)     # Controlled startup
modparam("uac_registrant", "reg_re_reg_limit_per_sec", 100)  # Normal re-registrations
modparam("uac_registrant", "retry_max_attempts", 10)        # More retry attempts
```

The implementation maintains full backward compatibility while providing robust retry mechanisms and rate limiting for improved registration reliability and system stability.
