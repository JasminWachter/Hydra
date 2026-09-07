# MulVAL Attack Graph JSON Output

The MulVAL pipeline now generates a structured JSON file (`AttackGraph.json`) containing all attack paths, nodes, edges, and analysis.

## JSON Structure

```json
{
  "attack_goal": "compromise(web01,user)",
  "total_paths": 197,
  "attack_paths": [...],
  "techniques_summary": {...},
  "nodes": {...},
  "edges": [...],
  "shortest_path_to_goal": {...}
}
```

### 1. Attack Paths

Each path includes:

-   `path_id`: Unique identifier
-   `rule_id`: MulVAL rule used
-   `technique`: ATT&CK technique name
-   `outcome`: The resulting predicate
-   `prerequisites`: List of required predicates
-   `hop_count`: Number of steps in this path

### 2. Techniques Summary

Statistics for each technique:

-   `path_count`: How many paths use this technique
-   `unique_outcomes`: Different outcomes achievable
-   `min_hops`/`max_hops`: Shortest and longest paths

### 3. Nodes

Graph nodes representing predicates:

-   `id`: Node identifier
-   `predicate`: Full predicate string
-   `name`: Predicate name
-   `arguments`: Predicate arguments
-   `type`: Node type (primitive/outcome)

### 4. Edges

Graph edges representing attack steps:

-   `from`: Source node ID
-   `to`: Target node ID
-   `technique`: Technique used
-   `rule_id`: Rule identifier
-   `path_id`: Associated path

### 5. Shortest Path Analysis

-   `min_hop_count`: Minimum hops to reach goal
-   `path_count`: Number of shortest paths
-   `paths`: Detailed shortest path steps
