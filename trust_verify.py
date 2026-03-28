import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

# --- BÖLÜM 1: GÖREV 1 - Dosya Hashleme ---
def generate_file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# --- BÖLÜM 1: GÖREV 2 - Manifest (metadata.json) Oluşturma ---
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

# --- BÖLÜM 1: GÖREV 3 - Bütünlük Kontrolü (Check) ---
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

# --- BÖLÜM 2: GÖREV 4 - RSA Anahtar Çifti Üretimi ---
def generate_rsa_keys():
    """Kullanıcı için 2048 bitlik Private ve Public anahtar çifti üretir."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- BÖLÜM 2: GÖREV 5 - Dijital İmza Oluşturma (Signing) ---
def sign_manifest(private_key, manifest_path):
    """metadata.json dosyasını okur, özetini alır ve Private Key ile imzalar."""
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

# --- BÖLÜM 2: GÖREV 6 - İmza Doğrulama (Verification) ---
def verify_signature(public_key, manifest_path, signature_path):
    """Alıcının Public Key kullanarak dosyanın imzasını doğrulaması işlemi."""
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

# --- PROJE VİDEOSU İÇİN TAM DEMO (TEST) KISMI ---
if __name__ == "__main__":
    print("\n" + "="*50)
    print("TrustVerify Aracına Hoş Geldiniz! (Tam Senaryo)")
    print("="*50)
    
    # 1. Ortam Hazırlığı
    test_klasoru = "test_verileri"
    if not os.path.exists(test_klasoru):
        os.makedirs(test_klasoru)
    test_dosyasi = os.path.join(test_klasoru, "cok_gizli_belge.txt")
    with open(test_dosyasi, "w", encoding="utf-8") as f:
        f.write("Bu belge Sender tarafindan olusturulmustur.")
        
    # --- GÖNDERİCİ (SENDER) İŞLEMLERİ ---
    print("\n[GÖNDERİCİ] 1. Dosyaların hash'leri alınıyor ve manifest (metadata.json) oluşturuluyor...")
    manifest_yolu = generate_manifest(test_klasoru)
    
    print("[GÖNDERİCİ] 2. RSA Anahtar Çifti Üretiliyor...")
    priv_key, pub_key = generate_rsa_keys()
    
    print("[GÖNDERİCİ] 3. Manifest dosyası Özel Anahtar (Private Key) ile imzalanıyor...")
    sig, sig_yolu = sign_manifest(priv_key, manifest_yolu)
    print("  -> İmza başarıyla metadata.json.sig olarak kaydedildi.")
    
    # --- ALICI (RECEIVER) İŞLEMLERİ (ORİJİNAL DOSYA) ---
    print("\n[ALICI] 4. Dosyalar teslim alındı. Doğrulama yapılıyor...")
    if verify_signature(pub_key, manifest_yolu, sig_yolu):
        print("  [+] BAŞARILI: İmza Geçerli! Manifest dosyası Gönderici'den gelmiş.")
        is_intact, tampered = verify_integrity(test_klasoru)
        if is_intact:
             print("  [+] BAŞARILI: Hash Kontrolü Tamam! Dosyalar bozulmamış.")
        else:
             print("  [-] HATA: Dosyalar değiştirilmiş!")
             for f in tampered:
                 print(f"      -> Bozulmuş dosya: {f}")
    
    # --- HACKER SALDIRISI SİMÜLASYONU ---
    print("\n" + "-"*50)
    print("[HACKER] 5. Yolda dosyaya müdahale ediliyor ve içerik değiştiriliyor!")
    with open(test_dosyasi, "a", encoding="utf-8") as f:
        f.write("\nGizli banka hesabi numarasi: TR00123...")
    
    print("[HACKER] Hacker, yeni içeriğe göre sahte bir manifest oluşturuyor...")
    generate_manifest(test_klasoru) # Hacker yeni hash hesapladı
    
    # --- ALICI (RECEIVER) İŞLEMLERİ (SABOTE EDİLMİŞ DOSYA) ---
    print("\n[ALICI] 6. Dosyalar teslim alındı. Tekrar doğrulama yapılıyor...")
    if verify_signature(pub_key, manifest_yolu, sig_yolu):
        print("  [+] BAŞARILI: İmza geçerli.")
        is_intact, tampered = verify_integrity(test_klasoru)
        if is_intact:
             print("  [+] BAŞARILI: Hash Kontrolü Tamam!")
        else:
             print("  [-] HATA: Dosyalar değiştirilmiş!")
             for f in tampered:
                 print(f"      -> Bozulmuş dosya: {f}")
    else:
        print("  [-] HATA: İMZA GEÇERSİZ! (Verification Failed)")
        print("      DİKKAT! Manifest dosyası sahte veya yolda değiştirilmiş.")
        print("      Hash kontrolüne gerek yok, kaynak zaten güvenilir değil.")
    print("="*50 + "\n")