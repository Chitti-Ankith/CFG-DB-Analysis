# CFG-DB-Analysis

# **Binary Analysis with angr, Neo4j, and PostgreSQL**

This repository contains scripts for extracting **Control Flow Graphs (CFGs)** from binary executables using **angr** and storing them in either **Neo4j (graph database)** or **PostgreSQL (relational database)**. These scripts allow us to analyze and detect potential security vulnerabilities

## **1. Scripts Overview**

### **1.1 cfg.py**

This script extracts a **Control Flow Graph (CFG)** for a single binary and stores the extracted information in **PostgreSQL** for relational querying.

#### **Workflow**:
- **Connects to PostgreSQL** (`psycopg2`).
- **Loads a binary** using **angr**.
- **Generates a CFG** using `CFGFast`.
- **Extracts function blocks** and inserts them into a `cfg_nodes` table:
  - Stores **function name, address, disassembled instructions, and instruction count**.
- **Extracts control flow edges** and inserts them into a `cfg_edges` table:
  - Stores **source node, destination node, and edge type (conditional/unconditional jumps).**

#### **Use Cases**:
- Query dead code (functions with no incoming edges).

---

### **1.2 multibinary_cfg_postgres.py**

This script **analyzes multiple binaries**, extracts **function signatures** (hashed function bodies), and stores them in **PostgreSQL** for function similarity analysis.

#### **Workflow**:
- **Connects to PostgreSQL** (`psycopg2`).
- **Creates a database table** (`function_signatures`) to store function hashes.
- **For each binary**:
  - Loads it in **angr** as a project.
  - Generates a **CFG using CFGFast**.
  - **For each function**:
    - Computes a **SHA-256 hash** based on the function's byte content.
    - Inserts function metadata (binary name, function name, address, hash signature) into PostgreSQL.

#### **Use Cases**:
- Detect duplicate functions across multiple binaries.
- Compare patched vs. unpatched binaries for changes in function structure.

---

### **1.3 multibinary_cfg_neo4j.py**

This script extracts Control Flow Graphs (CFGs) from multiple binaries and stores the extracted information in **Neo4j** for **graph-based analysis**.

#### **Workflow**:
- **Connects to Neo4j** using `py2neo.Graph(...)`.
- **Iterates over binaries** in a directory.
- **For each binary**:
  - Loads it in **angr** as a project.
  - Generates a **CFG using CFGFast**.
  - Creates a **Binary** node in **Neo4j** (avoids duplicates using `MERGE`).
  - Extracts **functions** from the CFG:
    - Creates a **Function** node and links it to the corresponding Binary node.
    - Extracts **Basic Blocks** inside the function and links them with `:HAS_BLOCK` relationships.
    - Extracts **Control Flow Edges** (`:FLOWS_TO`) to represent execution paths.

#### **Use Cases**:

- Query function relationships.
- Identify potentially vulnerable code paths.

---

## **2. Installation & Dependencies**

### **2.1 Required Libraries**
Install required dependencies using:
```bash
pip3 install angr psycopg2 py2neo
```

### **2.2 Setting Up Databases**
#### **PostgreSQL**
Ensure PostgreSQL is running and create a database:
```sql
CREATE DATABASE binary_analysis_db;
```
Ensure the required schema exists:
```sql
CREATE TABLE IF NOT EXISTS function_signatures (
    id SERIAL PRIMARY KEY,
    binary_name TEXT,
    function_name TEXT,
    start_address BIGINT,
    hash_signature TEXT
);

CREATE TABLE IF NOT EXISTS cfg_nodes (
    function_name TEXT,
    address BIGINT PRIMARY KEY,
    code TEXT,
    num_instructions INT
);

CREATE TABLE IF NOT EXISTS cfg_edges (
    from_node BIGINT,
    to_node BIGINT,
    edge_type TEXT,
    PRIMARY KEY (from_node, to_node)
);
```
#### **Neo4j**
Ensure Neo4j is running (default Bolt port `7687`).
Set up constraints (optional, for uniqueness enforcement):
```cypher
CREATE CONSTRAINT FOR (b:Binary) REQUIRE b.name IS UNIQUE;
CREATE CONSTRAINT FOR (f:Function) REQUIRE f.uuid IS UNIQUE;
CREATE CONSTRAINT FOR (bl:Block) REQUIRE bl.uuid IS UNIQUE;
```

---

## **3. Example Queries**

### **3.1 Largest Functions by Block Count (Neo4j)**
```cypher
MATCH (f:Function)-[:HAS_BLOCK]->(b:Block)
RETURN f.name AS functionName, COUNT(b) AS blockCount
ORDER BY blockCount DESC
LIMIT 10;
```

### **3.2 Functions Calling Dangerous APIs (Neo4j)**
```cypher
MATCH (f:Function)-[:CALLS]->(callee:Function)
WHERE callee.name IN ["strcpy", "gets", "sprintf"]
RETURN f.name AS vulnerableFunction, callee.name AS riskyAPI;
```

### **3.3 Detect Dead Code (PostgreSQL)**
```sql
SELECT function_name, address FROM cfg_nodes
WHERE address NOT IN (SELECT DISTINCT to_node FROM cfg_edges);
```

### **3.4 Find Functions with Identical Hashes (PostgreSQL)**
```sql
SELECT f1.binary_name, f1.function_name, f2.binary_name, f2.function_name
FROM function_signatures f1
JOIN function_signatures f2 ON f1.hash_signature = f2.hash_signature
WHERE f1.id < f2.id;
```

---

# **CGC Binaries**

The **CGC (Cyber Grand Challenge) binaries** binaries have been extracted from this [repo](https://github.com/zardus/cgc-bins/tree/master) for easier experimentation and analysis.

## **Other Resources**

- **CGC Challenge Source Code**: [GitHub Repository](https://github.com/CyberGrandChallenge/samples/)
- **In-depth CGC Dataset Analysis** by Lungetech: [Lungetech Analysis](http://www.lungetech.com/cgc-corpus/)
- **Lungetech CGC Challenge Corpus Repository**: [GitHub Repository](https://github.com/lungetech/cgc-challenge-corpus/)
