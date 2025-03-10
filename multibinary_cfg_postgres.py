import os
import hashlib
import angr
import psycopg2

DB_NAME = "binary_analysis_db"
DB_USER = "postgres"
DB_PASSWORD = "password"
DB_HOST = "localhost"
DB_PORT = 5432

def setup_database():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    cur = conn.cursor()
    
    # Table to store function-level info, including a 'hash_signature' column
    cur.execute("""
        CREATE TABLE IF NOT EXISTS function_signatures (
            id SERIAL PRIMARY KEY,
            binary_name TEXT,
            function_name TEXT,
            start_address BIGINT,
            hash_signature TEXT
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

def compute_function_hash(proj, func):
    """
    Compute a hash of the function by concatenating 
    its blocks' bytes and hashing the result.
    """
    m = hashlib.sha256()
    
    for block in func.blocks:
        block_bytes = proj.factory.block(block.addr).bytes
        m.update(block_bytes)
    
    return m.hexdigest()

def analyze_binary(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)
    # static analysis for speed
    cfg = proj.analyses.CFGFast()  
    
    # Insert function signatures into DB
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    cur = conn.cursor()
    
    binary_name = os.path.basename(binary_path)
    
    for func_addr, func in cfg.kb.functions.items():
        func_name = func.name
        
        # Compute a SHA-256 hash based on the function's byte content
        sig = compute_function_hash(proj, func)
        
        cur.execute("""
            INSERT INTO function_signatures (binary_name, function_name, start_address, hash_signature)
            VALUES (%s, %s, %s, %s)
        """, (binary_name, func_name, func_addr, sig))
    
    conn.commit()
    cur.close()
    conn.close()
    print(f"[+] Analyzed and stored function signatures for {binary_name}")

def main():
    setup_database()
    
    binaries_folder = "./Binaries/all_unpatched"
    
    for filename in os.listdir(binaries_folder):
        filepath = os.path.join(binaries_folder, filename)
        if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
            try:
                analyze_binary(filepath)
            except Exception as e:
                print(f"[-] Could not analyze {filepath}: {e}")
    
    print("Completed analysis of all binaries.")

if __name__ == "__main__":
    main()