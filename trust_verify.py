import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

# --- PART 1: TASK 1 - File Hashing ---
def generate_file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# --- PART 1: TASK 2 - Manifest (metadata.json) Generation ---
def generate_manifest(directory_path, output_json="metadata.json"):
    manifest = {}
    if not os.path.exists(directory_path):
        return None
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file == output_json or file.endswith('.sig') or file.startswith('.'):
                continue
            filepath = os.path.join(root, file)
            file_hash = generate_file_hash(filepath)
            if file_hash:
                rel_path = os.path.relpath(filepath, directory_path)
                manifest[rel_path] = file_hash
                
    output_path = os.path.join(directory_path, output_json)
    with open(output_path, "w", encoding="utf-8") as json_file:
        json.dump(manifest, json_file, indent=4)
    return output_path

# --- PART 1: TASK 3 - Integrity Check ---
def verify_integrity(directory_path, manifest_json="metadata.json"):
    manifest_path = os.path.join(directory_path, manifest_json)
    if not os.path.exists(manifest_path):
        return False
        
    with open(manifest_path, "r", encoding="utf-8") as json_file:
        saved_manifest = json.load(json_file)
        
    tampered_files = []
    for rel_path, saved_hash in saved_manifest.items():
        filepath = os.path.join(directory_path, rel_path)
        if not os.path.exists(filepath):
            tampered_files.append(rel_path)
            continue
            
        current_hash = generate_file_hash(filepath)
        if current_hash != saved_hash:
            tampered_files.append(rel_path)
            
    return len(tampered_files) == 0, tampered_files

# --- PART 2: TASK 4 - RSA Key Pair Generation ---
def generate_rsa_keys():
    """Generates a 2048-bit Private and Public key pair for the user."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- PART 2: TASK 5 - Digital Signature Creation (Signing) ---
def sign_manifest(private_key, manifest_path):
    """Reads metadata.json, computes its hash, and signs it with the Private Key."""
    with open(manifest_path, "rb") as f:
        manifest_data = f.read()
        
    signature = private_key.sign(
        manifest_data,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    sig_path = manifest_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)
    return signature, sig_path

# --- PART 2: TASK 6 - Signature Verification ---
def verify_signature(public_key, manifest_path, signature_path):
    """Receiver verifies the file signature using the Sender's Public Key."""
    with open(manifest_path, "rb") as f:
        manifest_data = f.read()
    with open(signature_path, "rb") as f:
        signature = f.read()
        
    try:
        public_key.verify(
            signature,
            manifest_data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# --- FULL DEMO FOR PROJECT VIDEO ---
if __name__ == "__main__":
    print("\n" + "="*50)
    print("Welcome to TrustVerify! (Full Scenario)")
    print("="*50)
    
    # 1. Environment Setup
    test_folder = "test_data"
    if not os.path.exists(test_folder):
        os.makedirs(test_folder)
    test_file = os.path.join(test_folder, "top_secret_document.txt")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("This document was created by the Sender.")
        
    # --- SENDER OPERATIONS ---
    print("\n[SENDER] 1. Hashing files and generating manifest (metadata.json)...")
    manifest_path = generate_manifest(test_folder)
    
    print("[SENDER] 2. Generating RSA Key Pair...")
    priv_key, pub_key = generate_rsa_keys()
    
    print("[SENDER] 3. Signing manifest with Private Key...")
    sig, sig_path = sign_manifest(priv_key, manifest_path)
    print("  -> Signature saved successfully as metadata.json.sig")
    
    # --- RECEIVER OPERATIONS (ORIGINAL FILE) ---
    print("\n[RECEIVER] 4. Files received. Running verification...")
    if verify_signature(pub_key, manifest_path, sig_path):
        print("  [+] SUCCESS: Signature Valid! Manifest came from the Sender.")
        is_intact, tampered = verify_integrity(test_folder)
        if is_intact:
             print("  [+] SUCCESS: Hash Check Passed! Files are intact.")
        else:
             print("  [-] ERROR: Files have been modified!")
             for f in tampered:
                 print(f"      -> Tampered file: {f}")
    
    # --- HACKER ATTACK SIMULATION ---
    print("\n" + "-"*50)
    print("[HACKER] 5. Intercepting and modifying the file in transit!")
    with open(test_file, "a", encoding="utf-8") as f:
        f.write("\nSecret bank account number: TR00123...")
    
    print("[HACKER] Hacker recomputes a fake manifest with new hashes...")
    generate_manifest(test_folder)
    
    # --- RECEIVER OPERATIONS (TAMPERED FILE) ---
    print("\n[RECEIVER] 6. Files received. Running verification again...")
    if verify_signature(pub_key, manifest_path, sig_path):
        print("  [+] SUCCESS: Signature valid.")
        is_intact, tampered = verify_integrity(test_folder)
        if is_intact:
             print("  [+] SUCCESS: Hash Check Passed!")
        else:
             print("  [-] ERROR: Files have been modified!")
             for f in tampered:
                 print(f"      -> Tampered file: {f}")
    else:
        print("  [-] ERROR: SIGNATURE INVALID! (Verification Failed)")
        print("      WARNING! Manifest is forged or has been altered in transit.")
        print("      No need to check hashes, the source is already untrusted.")
    print("="*50 + "\n")