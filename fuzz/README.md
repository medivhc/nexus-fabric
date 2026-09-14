# Fuzzing

优先 fuzz：

- packet / protocol parser
- RPC / wire input
- Workspace manifest / commit decode
- policy/rule parser
- untrusted metadata

每个 unsafe boundary 或复杂 parser 应有明确 fuzz target。
