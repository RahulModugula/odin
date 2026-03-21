def process_records(records, config, db, logger, cache):
    results = []
    for record in records:
        if record.get("type") == "A":
            if record.get("status") == "active":
                if record.get("priority") > 5:
                    for field in record.get("fields", []):
                        if field.get("required"):
                            if field.get("value") is None:
                                try:
                                    val = db.lookup(field["name"])
                                    if val:
                                        record[field["name"]] = val
                                        results.append(record)
                                    else:
                                        logger.warn(f"Missing {field['name']}")
                                except Exception:
                                    pass
                        else:
                            results.append(record)
                else:
                    results.append(record)
            elif record.get("status") == "pending":
                cache.invalidate(record["id"])
        elif record.get("type") == "B":
            if config.get("process_b"):
                results.append(record)
    return results
