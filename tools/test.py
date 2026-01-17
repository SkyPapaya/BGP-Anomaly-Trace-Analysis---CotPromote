import requests
import json

def debug_rpki_raw(prefix, asn, description):
    url = "https://stat.ripe.net/data/rpki-validation/data.json"
    params = {
        "resource": asn,
        "prefix": prefix,
        "sourceapp": "debug-test-script"
    }
    
    print(f"\n[{description}]")
    print(f"请求: AS{asn} 宣告 {prefix}")
    print(f"URL: {url}")
    
    try:
        resp = requests.get(url, params=params, timeout=10)
        print(f"HTTP状态码: {resp.status_code}")
        
        data = resp.json()
        # 打印原始的 validating_roas 信息，看看有没有匹配到任何记录
        validating_roas = data.get('data', {}).get('validating_roas', [])
        status = data.get('data', {}).get('status', 'N/A')
        
        print(f"API 返回状态 (status): {status}")
        print(f"关联 ROA 记录数: {len(validating_roas)}")
        
        # 如果是 unknown，打印完整的 data 方便分析
        if status == 'unknown':
            print("完整返回数据 (Debug):")
            print(json.dumps(data, indent=2))
            
    except Exception as e:
        print(f"请求报错: {e}")

if __name__ == "__main__":
    print("=== RPKI API 深度诊断 ===")
    
    # 1. 验证基准：Cloudflare (1.1.1.0/24 属于 AS13335) - 应该返回 'valid'
    debug_rpki_raw("1.1.1.0/24", "13335", "CASE 1: 正常的 Cloudflare (基准测试)")
    
    # 2. 验证无效：用 12389 宣告 Cloudflare - 应该返回 'invalid'
    debug_rpki_raw("1.1.1.0/24", "12389", "CASE 2: 伪造劫持 Cloudflare (功能测试)")
    
    # 3. 验证你的案例：Twitter 2022 - 可能会返回 'unknown'
    debug_rpki_raw("104.244.42.0/24", "12389", "CASE 3: Twitter 2022 劫持复现")
    
    # 4. 验证 Twitter 正常归属 - 看看 Twitter 现在是否有 ROA
    debug_rpki_raw("104.244.42.0/24", "13414", "CASE 4: Twitter 正常归属检测")