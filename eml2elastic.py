#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
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
"""

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable

# Email parsing
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header

# Elasticsearch
try:
    from elasticsearch import Elasticsearch, helpers
except Exception as e:
    Elasticsearch = None
    helpers = None

URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|ftp://|mailto:)[^\s<>"\')]+)'
)

def decode_str(s: Optional[str]) -> Optional[str]:
    if not s:
        return s
    try:
        # Handles RFC2047 encoded words
        return str(make_header(decode_header(s)))
    except Exception:
        return s

def get_addresses(msg, header_name: str) -> List[str]:
    vals = msg.get_all(header_name, [])
    if not vals:
        return []
    # We won't import email.utils.getaddresses for minimal deps; do a simple split.
    # For robust parsing, users can replace with email.utils.getaddresses().
    addrs: List[str] = []
    try:
        from email.utils import getaddresses
        for _, addr in getaddresses(vals):
            if addr:
                addrs.append(addr.strip())
    except Exception:
        for v in vals:
            for part in v.split(","):
                p = part.strip()
                if "<" in p and ">" in p:
                    inside = p[p.find("<")+1:p.rfind(">")].strip()
                    if inside:
                        addrs.append(inside)
                else:
                    if p:
                        addrs.append(p)
    return addrs

def get_first_body(msg) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (text_body, html_body)
    """
    text_body = None
    html_body = None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition", "") or "").lower()
            if ctype == "text/plain" and "attachment" not in disp and text_body is None:
                try:
                    text_body = part.get_content()
                except Exception:
                    try:
                        text_body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
                    except Exception:
                        pass
            elif ctype == "text/html" and "attachment" not in disp and html_body is None:
                try:
                    html_body = part.get_content()
                except Exception:
                    try:
                        html_body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
                    except Exception:
                        pass
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            payload = None
            try:
                payload = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", "replace")
            except Exception:
                pass
        if ctype == "text/plain":
            text_body = payload
        elif ctype == "text/html":
            html_body = payload
        else:
            # unknown single-part, leave empty
            pass
    return text_body, html_body

def iter_attachments(msg) -> Iterable[Tuple[str, str, bytes]]:
    """
    Yields (filename, content_type, content_bytes)
    """
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get("Content-Disposition", "") or "").lower()
        if "attachment" in disp or part.get_filename():
            filename = decode_str(part.get_filename())
            ctype = part.get_content_type() or "application/octet-stream"
            try:
                data = part.get_payload(decode=True)
                if data is None:
                    # Some EMLs might include base64 in body
                    raw = part.get_payload()
                    try:
                        data = base64.b64decode(raw, validate=False)
                    except Exception:
                        data = raw.encode("utf-8", "replace") if isinstance(raw, str) else b""
            except Exception:
                data = b""
            yield filename or "", ctype, data

def parse_received(headers: List[str]) -> List[str]:
    # "Received" headers are numerous; keep raw strings for now.
    return headers or []

def parse_spf(h: Optional[str]) -> Optional[str]:
    if not h:
        return None
    # naive: look for "pass", "fail", "softfail", "neutral"
    m = re.search(r'\b(pass|fail|softfail|neutral|temperror|permerror)\b', h, re.I)
    return {"status": (m.group(1).lower() if m else None), "raw": h}

def parse_dkim(sig: Optional[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not sig:
        return out
    for kv in sig.split(";"):
        kv = kv.strip()
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k.strip()] = v.strip()
    # Common keys: v, a, c, d (domain), s (selector), bh (body hash), b (signature), t (ts)
    return out

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def safe_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def eml_to_doc(path: Path, store_attach_dir: Optional[Path]) -> Dict[str, Any]:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Basic headers
    hdr_from = decode_str(msg.get("From"))
    hdr_subject = decode_str(msg.get("Subject"))
    hdr_date = msg.get("Date")
    hdr_message_id = msg.get("Message-ID")
    hdr_return_path = decode_str(msg.get("Return-Path"))
    hdr_reply_to = decode_str(msg.get("Reply-To"))
    hdr_to = [decode_str(x) for x in msg.get_all("To", [])]
    hdr_cc = [decode_str(x) for x in msg.get_all("Cc", [])]
    hdr_bcc = [decode_str(x) for x in msg.get_all("Bcc", [])]

    # Addresses (normalized list)
    to_addrs = get_addresses(msg, "To")
    cc_addrs = get_addresses(msg, "Cc")
    bcc_addrs = get_addresses(msg, "Bcc")
    from_addrs = get_addresses(msg, "From")

    # Authentication / routing
    received_list = parse_received(msg.get_all("Received", []))
    spf_result = parse_spf(msg.get("Received-SPF"))
    dkim_raw = msg.get("DKIM-Signature")
    dkim = parse_dkim(dkim_raw) if dkim_raw else {}

    x_headers = {k: v for (k, v) in msg.items() if k.lower().startswith("x-")}

    # Bodies
    text_body, html_body = get_first_body(msg)

    # URLs
    urls_text = URL_REGEX.findall(text_body or "")
    urls_html = URL_REGEX.findall(html_body or "")
    urls = sorted(set(urls_text + urls_html))

    # Attachments
    attachments_meta = []
    for fname, ctype, data in iter_attachments(msg):
        sha256 = sha256_bytes(data) if data else None
        size = len(data) if data else 0
        saved_path = None
        if store_attach_dir and data:
            # sanitize extension by content-type or filename
            ext = ""
            if fname and "." in fname:
                ext = "." + fname.split(".")[-1].strip().strip('"').strip("'")
            outname = f"{sha256}{ext}" if sha256 else (fname or "unknown.bin")
            dest = store_attach_dir / outname
            try:
                safe_write(dest, data)
                saved_path = str(dest)
            except Exception:
                saved_path = None
        attachments_meta.append({
            "filename": fname,
            "content_type": ctype,
            "size": size,
            "sha256": sha256,
            "saved_path": saved_path
        })

    # Date normalization
    iso_date = None
    if hdr_date:
        try:
            from email.utils import parsedate_to_datetime
            d = parsedate_to_datetime(hdr_date)
            iso_date = d.isoformat()
        except Exception:
            iso_date = hdr_date

    doc: Dict[str, Any] = {
        "source_path": str(path),
        "message_id": hdr_message_id,
        "from_raw": hdr_from,
        "from": [{"name": "", "address": a} for a in from_addrs],
        "reply_to": hdr_reply_to,
        "to_raw": hdr_to,
        "to": [{"name": "", "address": a} for a in get_addresses(msg, "To")],
        "cc": [{"name": "", "address": a} for a in get_addresses(msg, "Cc")],
        "bcc": [{"name": "", "address": a} for a in get_addresses(msg, "Bcc")],
        "subject": hdr_subject or "",
        "date": iso_date,
        "headers": {
            "return_path": hdr_return_path,
            "received": received_list,
            "received_spf": spf_result,
            "dkim": dkim,
            "x_headers": x_headers
        },
        "body": {
            "text": text_body,
            "html": html_body
        },
        "urls": urls,
        "attachments": attachments_meta
    }
    return doc

def build_mapping() -> Dict[str, Any]:
    return {
        "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "analysis": {
                "normalizer": {
                    "lowercase_normalizer": {
                        "type": "custom",
                        "filter": ["lowercase"]
                    }
                }
            }
        },
        "mappings": {
            "dynamic": True,
            "properties": {
                "message_id": {"type": "keyword"},
                "date": {"type": "date"},
                "from": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "to": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "cc": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "bcc": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "from_raw": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "to_raw": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "subject": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "urls": {"type": "keyword"},
                "attachments": {
                    "properties": {
                        "filename": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                        "content_type": {"type": "keyword"},
                        "size": {"type": "long"},
                        "sha256": {"type": "keyword"},
                        "saved_path": {"type": "keyword"}
                    }
                },
                "headers": {
                    "properties": {
                        "return_path": {"type": "keyword"},
                        "received": {"type": "text"},
                        "received_spf": {"type": "keyword"},
                        "dkim": {"type": "object", "enabled": True},
                        "x_headers": {"type": "object", "enabled": True}
                    }
                },
                "body": {
                    "properties": {
                        "text": {"type": "text"},
                        "html": {"type": "text"}
                    }
                },
                "source_path": {"type": "keyword"}
            }
        }
    }

def ensure_index(es, index_name: str) -> None:
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name, **build_mapping())

def bulk_actions(index: str, docs: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for doc in docs:
        # Use message_id if available to avoid duplicates
        _id = doc.get("message_id") or sha256_bytes(doc.get("source_path","").encode("utf-8"))
        yield {
            "_index": index,
            "_id": _id,
            "_op_type": "index",
            "_source": doc
        }

def collect_emls(input_path: Path) -> List[Path]:
    if input_path.is_file() and input_path.suffix.lower() == ".eml":
        return [input_path]
    emls: List[Path] = []
    for p in input_path.rglob("*.eml"):
        if p.is_file():
            emls.append(p)
    return emls

def process_one(path: Path, attach_dir: Optional[Path]) -> Dict[str, Any]:
    try:
        return eml_to_doc(path, attach_dir)
    except Exception as e:
        return {
            "source_path": str(path),
            "parse_error": str(e)
        }

def main():
    ap = argparse.ArgumentParser(description="Parse EML files and index into Elasticsearch")
    ap.add_argument("--input", required=True, help="Path to a .eml file or a directory containing .eml files")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL (default: %(default)s)")
    ap.add_argument("--index", default="emails", help="Index name (default: %(default)s)")
    ap.add_argument("--batch-size", type=int, default=500, help="Bulk batch size (default: %(default)s)")
    ap.add_argument("--store-attachments", default=None, help="Directory to store attachments (optional)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Parallel workers (default: %(default)s)")
    ap.add_argument("--dry-run", action="store_true", help="Parse and print sample JSON without indexing")
    args = ap.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"[ERROR] Input path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    attach_dir = Path(args.store_attachments).expanduser().resolve() if args.store_attachments else None
    if attach_dir:
        attach_dir.mkdir(parents=True, exist_ok=True)

    eml_paths = collect_emls(input_path)
    if not eml_paths:
        print("[WARN] No .eml files found.", file=sys.stderr)
        sys.exit(0)

    print(f"[INFO] Found {len(eml_paths)} EML files")
    docs: List[Dict[str, Any]] = []

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for doc in ex.map(lambda p: process_one(p, attach_dir), eml_paths, chunksize=10):
            docs.append(doc)

    if args.dry_run:
        for d in docs[:5]:
            print(json.dumps(d, ensure_ascii=False)[:2000] + ("..." if len(json.dumps(d, ensure_ascii=False))>2000 else ""))
        print(f"[INFO] Parsed {len(docs)} docs (dry-run).")
        return

    if Elasticsearch is None or helpers is None:
        print("[ERROR] 'elasticsearch' package not available. Install with: pip install elasticsearch>=8", file=sys.stderr)
        sys.exit(2)

    es = Elasticsearch(args.es)
    ensure_index(es, args.index)

    # Bulk index
    total = 0
    for i in range(0, len(docs), args.batch_size):
        batch = docs[i:i+args.batch_size]
        ok, errs = helpers.bulk(es, bulk_actions(args.index, batch), raise_on_error=False)
        if errs:
            import pprint
            print("[ERROR] sample errors:")
            pprint.pprint(errs[:3], stream=sys.stderr)
        total += ok
        if errs:
            print(f"[WARN] Bulk errors in batch starting {i}: {len(errs)} errors", file=sys.stderr)
    print(f"[INFO] Indexed {total}/{len(docs)} documents into '{args.index}' at {args.es}")

if __name__ == "__main__":
    main()
