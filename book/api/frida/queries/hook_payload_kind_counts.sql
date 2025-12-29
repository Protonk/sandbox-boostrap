-- Count hook payload kinds across all agent send() events.
SELECT
  hook_payload_kind,
  COUNT(*) AS event_count
FROM events
WHERE source = 'agent' AND kind = 'send'
GROUP BY hook_payload_kind
ORDER BY event_count DESC, hook_payload_kind ASC;

