# CARTON usage examples (Sonoma 14.4.1)

These snippets show how to lean on CARTON instead of raw experiment outputs. All paths are stable as long as `book/graph/carton/CARTON.json` is unchanged. The API raises `UnknownOperationError` for op names outside the CARTON vocab and `CartonDataError` if a mapping is missing or out of sync with the manifest; catch those when probing.

- **Runtime signature → probes + profile path**
  ```python
  from book.api.carton import carton_query
  info = carton_query.runtime_signature_info("bucket4:v1_read")
  print(info["probes"])           # allow/deny outcomes captured in runtime_signatures.json
  print(info["runtime_profile"])  # compiled runtime blob path tied to this signature
  ```

- **Who exercises an operation?**
  ```python
  from book.api.carton import carton_query
  mapping = carton_query.profiles_and_signatures_for_operation("file-read*")
  print(mapping["system_profiles"])     # system profile digests that include op id 21
  print(mapping["runtime_signatures"])  # runtime signatures that probe the same op
  ```

- **Find under-covered operations when planning new experiments**
  ```python
  from book.api.carton import carton_query
  for entry in carton_query.ops_with_low_coverage(threshold=0):
      print(entry["name"], entry["counts"])
  ```

See `book/profiles/golden-triple/CaseStudy_bucket4.md` for a worked SBPL→blob→runtime example that ties back to these CARTON queries.
