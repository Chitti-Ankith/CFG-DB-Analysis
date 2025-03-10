import psycopg2
import angr

conn = psycopg2.connect("dbname=cfg_analysis user=postgres password=password")
cur = conn.cursor()

binary_path = "./Binaries/all_unpatched/CADET_00001"

proj = angr.Project(binary_path, auto_load_libs=False)

# Insert function blocks (CFG nodes)
for func in cfg.functions.values():
    for block in func.blocks:
        cur.execute(
            "INSERT INTO cfg_nodes (function_name, address, code, num_instructions) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (address) DO NOTHING",
            (func.name, block.addr, proj.factory.block(block.addr).capstone.insns, len(block.insts))
        )

# Insert control flow edges
for edge in cfg.graph.edges():
    cur.execute(
        "INSERT INTO cfg_edges (from_node, to_node, edge_type) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        (edge[0].addr, edge[1].addr, "Unconditional" if edge[2]['jumpkind'] == "Ijmp" else "Conditional")
    )

conn.commit()
cur.close()
conn.close()