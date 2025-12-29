-- Summarize runner stage timing by stage name.
SELECT
  runner.stage AS stage,
  MIN(t_ns) AS t0_ns,
  MAX(t_ns) AS t1_ns,
  COUNT(*) AS event_count
FROM events
WHERE source = 'runner' AND kind = 'stage'
GROUP BY stage
ORDER BY t0_ns ASC, stage ASC;

