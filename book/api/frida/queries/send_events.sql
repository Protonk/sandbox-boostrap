-- List agent send() events in sequence order.
SELECT
  seq,
  t_ns,
  pid,
  hook_payload_kind
FROM events
WHERE source = 'agent' AND kind = 'send'
ORDER BY seq ASC;

