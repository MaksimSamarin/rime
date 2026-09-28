# Rime 0.2.0-rc6

Creating a user through the unified console now explicitly validates inbound
selection. Pydantic did not validate an omitted default `inbounds` field, so the
previous create path accidentally excluded every VLESS inbound while external
Hy2 links remained present. New all-node users now receive the configured VLESS
endpoints as well. Selected-node filtering and disabled-account semantics remain
in force. Existing users are not modified automatically.

Affected existing accounts can be repaired by updating only their enabled
inbounds through the user API. Preserve the existing proxy UUID, subscription URL,
status, limits, expiry, tags and node policy. Do not apply a bulk repair to users
with deliberate protocol restrictions.

`tests/console_creation.py` exercises the actual console API with two native
inbounds, external Hy2 endpoints, real VLESS payload, editing, selected-node
filtering, disabled creation and panel restart.
