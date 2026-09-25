# Per-Registrant User-Agent Support

## Overview

This customization adds support for a per-registrant `User-Agent` header in the `uac_registrant` module. Each registrant can now have its own User-Agent string stored in the database, which will be included in outgoing REGISTER and UNREGISTER SIP packets.

If the `user_agent` value is NULL or empty for a registrant, no User-Agent header is added (preserving the original behavior).

## Backward Compatibility

This feature is **disabled by default**. The module parameter `enable_custom_user_agent` must be explicitly set to `1` to activate it. When disabled (the default), the module does not query the `user_agent` column at all, so it works perfectly with the old database schema that does not have the column.

## Enabling the Feature

### Step 1: Add the database column

```sql
ALTER TABLE uac_registrant ADD COLUMN user_agent VARCHAR(255) DEFAULT NULL;
```

### Step 2: Enable in OpenSIPS config

```
modparam("uac_registrant", "enable_custom_user_agent", 1)
```

### Step 3: Restart or reload

Restart OpenSIPS or reload the registrants via MI.

## Database Changes

Add the `user_agent` column to the `uac_registrant` table (only needed when enabling the feature):

```sql
ALTER TABLE uac_registrant ADD COLUMN user_agent VARCHAR(255) DEFAULT NULL;
```

### Updated Table Schema

| Field       | Type         | Description                              |
|-------------|--------------|------------------------------------------|
| user_agent  | varchar(255) | User-Agent header value for this registrant. NULL or empty means no header is sent. |

### Example Usage

```sql
-- Set a custom User-Agent for a specific registrant
UPDATE uac_registrant SET user_agent = 'MyPBX/1.0' WHERE aor = 'sip:user@example.com';

-- Clear the User-Agent (reverts to no header)
UPDATE uac_registrant SET user_agent = NULL WHERE aor = 'sip:user@example.com';
```

After updating the database, reload the registrant via MI:

```
opensipsctl mi reg_reload
```

## Module Parameters

### enable_custom_user_agent (integer, default 0)

Controls whether the per-registrant User-Agent feature is active. Set to `1` to enable.

```
modparam("uac_registrant", "enable_custom_user_agent", 1)
```

When set to `0` (default), the module does not attempt to read the `user_agent` column from the database, ensuring full backward compatibility with existing schemas.

### user_agent_column (string, default "user_agent")

Overrides the DB column name used for the User-Agent value. Only relevant when `enable_custom_user_agent` is set to `1`.

```
modparam("uac_registrant", "user_agent_column", "user_agent")
```

## SIP Behavior

When a registrant has a non-empty `user_agent` value, the outgoing REGISTER and UNREGISTER requests will include:

```
User-Agent: <value from database>
```

The per-registrant value **replaces** the default OpenSIPS User-Agent header (set by `server_signature`) for that request. This is done by temporarily swapping the global `user_agent_header` before the TM module builds the SIP message, then restoring it afterward. This avoids duplicate User-Agent headers.

If no per-registrant `user_agent` is set, the default OpenSIPS User-Agent header is used as before.

## MI reg_list Output

The `reg_list` MI command now includes a `user_agent` field for each registrant that has one configured:

```json
{
  "AOR": "sip:user@example.com",
  "expires": 3600,
  "state": "REGISTERED_STATE",
  "user_agent": "MyPBX/1.0"
}
```

If no user_agent is set, the field is omitted from the output.

## Files Modified

| File | Change |
|------|--------|
| `reg_db_handler.h` | Added `USER_AGENT_COL` constant, bumped `REG_TABLE_TOTAL_COL_NO` from 13 to 14, added `extern str user_agent_column` |
| `reg_db_handler.c` | Added `user_agent_column` str variable, column index, query setup, and DB value extraction in `load_reg_info_from_db()` |
| `reg_records.h` | Added `str user_agent` field to `uac_reg_map_t` and `reg_record_t` structs |
| `reg_records.c` | Added `user_agent` to memory size calculation and string copy in `add_record()` |
| `registrant.c` | Increased `extra_hdrs_buf` from 512 to 1024, added `user_agent_hdr` string, added `user_agent_column` module parameter, injected User-Agent header in `send_register()` and `send_unregister()`, added `user_agent` to `reg_list` MI output |
