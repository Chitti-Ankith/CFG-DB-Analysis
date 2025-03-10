import os
import angr
from py2neo import Graph, Node, Relationship

NEO4J_URI = "bolt://localhost:7687"    # Adjust if Neo4j is running elsewhere
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "password"

BINARIES_FOLDER = "./Binaries/all_unpatched"

# Connect to Neo4j
graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def create_or_get_binary_node(binary_name):
    """
    Creates (or retrieves) a 'Binary' node in Neo4j.
    """
    # Use MERGE to ensure we don't create duplicates
    query = """
    MERGE (b:Binary {name: $name})
    RETURN b
    """
    result = graph.run(query, name=binary_name).data()
    return result[0]['b']  # 'b' is the alias for the matched/created node

def create_function_node(binary_node, func):
    """
    Creates a 'Function' node with some properties:
      - name
      - start_address
    Then connects it to the parent 'Binary' node via a relationship.
    """
    # Create a unique ID or address-based identifier (func.addr is unique in each binary)
    func_uuid = f"{binary_node['name']}:{hex(func.addr)}"

    query = """
    MERGE (f:Function {uuid: $uuid})
    SET f.name = $name,
        f.start_address = $addr
    MERGE (b:Binary {name: $binary_name})
    MERGE (b)-[:CONTAINS_FUNCTION]->(f)
    RETURN f
    """
    result = graph.run(query,
                       uuid=func_uuid,
                       name=func.name,
                       addr=func.addr,
                       binary_name=binary_node['name']).data()
    return result[0]['f']

def create_block_node(func_node, block_addr, block_size):
    """
    Creates a 'Block' node and links it to the parent 'Function'.
    """
    block_uuid = f"{func_node['uuid']}:{hex(block_addr)}"

    query = """
    MERGE (bl:Block {uuid: $uuid})
    SET bl.address = $addr,
        bl.size = $size
    MERGE (f:Function {uuid: $func_uuid})
    MERGE (f)-[:HAS_BLOCK]->(bl)
    RETURN bl
    """
    result = graph.run(query,
                       uuid=block_uuid,
                       addr=block_addr,
                       size=block_size,
                       func_uuid=func_node['uuid']).data()
    return result[0]['bl']

def create_edge_relationship(src_block, dst_block):
    """
    Creates a relationship 'FLOWS_TO' from src_block to dst_block.
    """
    query = """
    MERGE (src:Block {uuid: $src_uuid})
    MERGE (dst:Block {uuid: $dst_uuid})
    MERGE (src)-[:FLOWS_TO]->(dst)
    """
    graph.run(query, src_uuid=src_block['uuid'], dst_uuid=dst_block['uuid'])

# EXTRACT CFG & STORE IN NEO4J
def analyze_binary(file_path):
    print(f"[+] Analyzing binary: {file_path}")
    binary_name = os.path.basename(file_path)

    try:
        proj = angr.Project(file_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # Create or get 'Binary' node in the graph
        binary_node = create_or_get_binary_node(binary_name)

        # Iterate over discovered functions
        for func_addr, func in cfg.kb.functions.items():
            func_node = create_function_node(binary_node, func)

            # For each basic block in the function
            block_map = {}
            for block in func.blocks:
                block_node = create_block_node(func_node, block.addr, block.size)
                block_map[block.addr] = block_node

            # Create edges (CFG transitions)
            for block in func.blocks:
                block_node = block_map[block.addr]
                # Each block node in angr can have successors
                cfg_node = cfg.model.get_any_node(block.addr)
                if cfg_node:
                    for successor in cfg_node.successors:
                        dst_addr = successor.addr
                        if dst_addr in block_map:
                            dst_block_node = block_map[dst_addr]
                            create_edge_relationship(block_node, dst_block_node)

        print(f"[+] Finished storing CFG for {binary_name} in Neo4j.")

    except Exception as e:
        print(f"[-] Error analyzing {file_path}: {e}")

# Perform Analysis on the extracted data
def perform_analysis():
    # Some sample queries.
    queries = {
        "Top 10 Largest Functions": """
            MATCH (f:Function)-[:HAS_BLOCK]->(b:Block)
            RETURN f.name AS functionName, COUNT(b) AS blockCount
            ORDER BY blockCount DESC
            LIMIT 10
        """,
        "Functions Calling Dangerous APIs": """
            MATCH (f:Function)-[:CALLS]->(callee:Function)
            WHERE callee.name IN ["strcpy", "gets", "sprintf"]
            RETURN f.name AS vulnerableFunction, callee.name AS riskyAPI;
        """,
        "Functions with High Cyclomatic Complexity": """
            MATCH (f:Function)
            WHERE f.cyclomatic_complexity > 50
            RETURN f.name, f.cyclomatic_complexity
            ORDER BY f.cyclomatic_complexity DESC
            LIMIT 10;
        """,
        "Identifying Suspicious Control Flow Patterns": """
            MATCH (f:Function)-[r:HAS_BLOCK|FLOWS_TO*]->(b:Block)
            WHERE r.type = "indirect"
            WITH f, count(r) as indirectEdges
            WHERE indirectEdges > 10
            RETURN f.name, indirectEdges
        """
    }

    # Execute and print results
    for desc, query in queries.items():
        print(f"\n{desc}:")
        results = graph.run(query).data()
        for row in results:
            print(row)


def main():
    folder_path = BINARIES_FOLDER

    # Loop over files in the directory
    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        # Check if it's a file and executable permission
        if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
            analyze_binary(filepath)

    print("[+] All binaries analyzed and stored in Neo4j.")

if __name__ == "__main__":
    main()
