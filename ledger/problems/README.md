# GMF Problem Registry (immutable-by-hash)

- Server only issues `problem_id` and `statement_hash`.
- Clients fetch statement by hash from this registry (or mirror).
- The file content MUST match sha256(statement_file_bytes).
