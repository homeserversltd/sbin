#!/bin/bash

WATCH_DIR="/mnt/nas/books/upload"
LIBRARY_PATH="/mnt/nas/books"

mkdir -p "$WATCH_DIR"

inotifywait -m "$WATCH_DIR" -e create -e moved_to --format '%w%f' |
  while read filepath; do
    if [[ "$filepath" =~ \.(pdf|epub|mobi|azw|azw3)$ ]]; then
      echo "[$(date)] Processing: $(basename "$filepath")"
      if calibredb add "$filepath" --library-path="$LIBRARY_PATH" 2>&1; then
        echo "[$(date)] Added and removing: $(basename "$filepath")"
        rm -f "$filepath"
      else
        echo "[$(date)] Duplicate or failed, removing: $(basename "$filepath")"
        rm -f "$filepath"
      fi
    fi
  done

