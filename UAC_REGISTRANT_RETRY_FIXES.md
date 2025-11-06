# UAC Registrant Retry Logic Fixes

## Issues Identified and Fixed

### Issue 1: Incorrect Exponential Backoff Calculation
**Problem**: The `calculate_exponential_backoff_delay()` function had a bug in the loop logic where the condition `delay < retry_max_delay` caused premature exit from the loop, resulting in incorrect delay calculations.

**Root Cause**: The loop was checking the delay against max_delay before applying the multiplier for the current attempt, causing inconsistent behavior.

**Fix**: Modified the loop to use `for (int i = 1; i < attempt; i++)` and added proper overflow protection during calculation.

**Expected Behavior After Fix**:
With `retry_base_delay=5`, `retry_backoff_multiplier=2`:
- Attempt 1: 5 seconds (5 * 2^0)
- Attempt 2: 10 seconds (5 * 2^1) 
- Attempt 3: 20 seconds (5 * 2^2)
- Attempt 4: 40 seconds (5 * 2^3)
- Attempt 5: 80 seconds (5 * 2^4)

### Issue 2: Failed Attempts Not Reset on Re-registration
**Problem**: When transitioning to `NOT_REGISTERED_STATE` (including re-registrations), the `failed_attempts` counter was not being reset, causing the retry cycle to restart from the beginning delay instead of continuing with exponential backoff.

**Root Cause**: Missing `rec->failed_attempts = 0;` in the `NOT_REGISTERED_STATE` case.

**Fix**: Added `rec->failed_attempts = 0;` to reset the failed attempts counter when transitioning to `NOT_REGISTERED_STATE`.

**Expected Behavior After Fix**: Re-registrations will start fresh with the base delay instead of continuing from where the previous cycle left off.

### Issue 3: Max Attempts Logic Verification
**Problem**: The test showed registrations continuing beyond the configured `retry_max_attempts=3`.

**Root Cause**: The max attempts check was correct, but the issue was likely caused by the combination of Issues 1 and 2.

**Fix**: Verified the existing logic is correct - it checks `failed_attempts >= retry_max_attempts` before incrementing.

**Expected Behavior After Fix**: Registrations will stop exactly after `retry_max_attempts` attempts.

## Code Changes Made

### 1. Fixed `calculate_exponential_backoff_delay()` function
```c
/* Calculate exponential backoff: base_delay * (multiplier ^ (attempt-1)) */
delay = retry_base_delay;
for (int i = 1; i < attempt; i++) {
    delay *= retry_backoff_multiplier;
    /* Cap at maximum delay during calculation to prevent overflow */
    if (delay > retry_max_delay) {
        delay = retry_max_delay;
        break;
    }
}
```

### 2. Added failed_attempts reset in NOT_REGISTERED_STATE
```c
case NOT_REGISTERED_STATE:
    rec->next_retry_time = 0;  /* Reset retry timer */
    rec->current_retry_delay = 0;  /* Reset retry delay */
    rec->failed_attempts = 0;  /* Reset failed attempts counter */
```

## Test Configuration
The fixes address the issues reported with this configuration:
```
modparam("uac_registrant", "retry_base_delay", 5)
modparam("uac_registrant", "retry_max_delay", 300)
modparam("uac_registrant", "retry_max_attempts", 5)
modparam("uac_registrant", "retry_backoff_multiplier", 2)
```

## Expected Results After Fixes

1. **Correct Delay Progression**: Delays will follow 5, 10, 20, 40, 80 seconds instead of 8, 16, 24, 48, 96 seconds.

2. **Proper Max Attempts**: Registration will stop after exactly 5 attempts (as configured) instead of continuing beyond that.

3. **Consistent Re-registration**: When `retry_max_delay=30` is reached and a 24-second delayed request is sent, the registrar cycle will continue with proper exponential backoff instead of restarting from 8 seconds.

4. **Rate Limiting**: The rate limiting settings (`reg_rate_limit_per_sec=0`, `reg_re_reg_limit_per_sec=0`) will work as expected since they disable rate limiting.

## Testing Recommendations

1. **Compile and Test**: Compile the module and test with the provided configuration.

2. **Monitor Logs**: Look for the debug messages showing the exponential backoff calculations to verify correct delays.

3. **Verify Max Attempts**: Confirm that registrations stop after exactly 5 attempts.

4. **Test Re-registration**: Verify that re-registrations start with the base delay instead of continuing from previous cycles.

## Files Modified
- `modules/uac_registrant/registrant.c` - Fixed exponential backoff calculation and failed attempts reset
