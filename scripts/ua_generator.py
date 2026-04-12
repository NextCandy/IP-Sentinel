import random
import os

# ==========================================
# IP-Sentinel 超大型高保真指纹工厂 (V3.1.5)
# 无需第三方库，直接生成千万级组合的真实指纹
# ==========================================

def generate_chrome_version():
    # 模拟 2024 年主流 Chrome 内核号 (122 - 125)
    major = random.randint(122, 125)
    build = random.randint(5000, 6500)
    patch = random.randint(10, 150)
    return f"{major}.0.{build}.{patch}"

def generate_windows_ua(count=1000):
    uas = set()
    while len(uas) < count:
        # 现代 Windows UA 已经固化为 Windows NT 10.0
        uas.add(f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{generate_chrome_version()} Safari/537.36")
    return list(uas)

def generate_macos_ua(count=1000):
    uas = set()
    while len(uas) < count:
        mac_os_minor = random.randint(11, 15)
        mac_os_patch = random.randint(1, 6)
        if random.choice([True, False]):
            # Chrome on Mac
            uas.add(f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{mac_os_minor}_{mac_os_patch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{generate_chrome_version()} Safari/537.36")
        else:
            # Safari on Mac
            safari_build = f"605.1.{random.randint(10, 15)}"
            safari_version = f"17.{random.randint(1, 4)}"
            uas.add(f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{mac_os_minor}_{mac_os_patch}) AppleWebKit/{safari_build} (KHTML, like Gecko) Version/{safari_version} Safari/{safari_build}")
    return list(uas)

def generate_ios_ua(count=1000):
    uas = set()
    devices = ["iPhone", "iPad"]
    while len(uas) < count:
        device = random.choice(devices)
        ios_major = random.randint(16, 17)
        ios_minor = random.randint(1, 5)
        ios_patch = random.randint(1, 3)
        safari_build = f"605.1.{random.randint(10, 15)}"
        safari_version = f"{ios_major}.{random.choice(['0', '1', '2', '3'])}"
        
        uas.add(f"Mozilla/5.0 ({device}; CPU {'iPhone ' if device=='iPhone' else ''}OS {ios_major}_{ios_minor}_{ios_patch} like Mac OS X) AppleWebKit/{safari_build} (KHTML, like Gecko) Version/{safari_version} Mobile/15E148 Safari/604.1")
    return list(uas)

def generate_android_ua(count=1000):
    uas = set()
    # 主流 Android 机型库
    models = ["Pixel 8 Pro", "Pixel 8", "Pixel 7a", "Pixel 7 Pro", "SM-S928B", "SM-S928U", "SM-S918B", "SM-A546B", "SM-A346B", "23113RKC6C", "23049PCD8G", "CPH2437", "V2227A", "PGT-AN10", "NX729J"]
    while len(uas) < count:
        android_ver = random.randint(12, 14)
        model = random.choice(models)
        uas.add(f"Mozilla/5.0 (Linux; Android {android_ver}; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{generate_chrome_version()} Mobile Safari/537.36")
    return list(uas)

if __name__ == "__main__":
    # 确保输出目录存在
    os.makedirs('data', exist_ok=True)
    
    # 严格按照“绝对坐标”顺序生成 4000 条数据
    pool = []
    pool.extend(generate_windows_ua(1000))  # 行 1-1000
    pool.extend(generate_macos_ua(1000))    # 行 1001-2000
    pool.extend(generate_ios_ua(1000))      # 行 2001-3000
    pool.extend(generate_android_ua(1000))  # 行 3001-4000
    
    with open('data/user_agents.txt', 'w') as f:
        for ua in pool:
            f.write(ua + '\n')
            
    print(f"✅ 成功生成 4000 条高保真绝对坐标指纹库！")