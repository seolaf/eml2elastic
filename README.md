eml_to_elastic.py
-----------------
Parse EML files (headers, bodies, attachments), transform to JSON, and index into Elasticsearch.

Usage:
  python eml_to_elastic.py --input /path/to/emls --es http://localhost:9200 --index emails \
      [--batch-size 500] [--store-attachments /path/to/save] [--dry-run]

Notes:
- Requires: elasticsearch>=8.0.0
- Safe defaults: we DO NOT store raw attachment bytes in Elasticsearch; only metadata + hashes.
- If --store-attachments is given, attachments will be written to disk by sha256.<ext>.
