import pybgpstream

# 初始化流，模拟 RCAgent 的数据专家工具 [cite: 6]
stream = pybgpstream.BGPStream(
    project="ris-live"
)

print("[*] 正在通过底层 C 库连接 RIPE RIS 实时流...")

try:
    for i, elem in enumerate(stream):
        # 提取 AS-Path 和 Prefix，这是 LogSage 识别线索的基础 
        as_path = elem.fields.get("as-path")
        prefix = elem.fields.get("prefix")
        print(f"[{i}] 收到更新: {prefix} | 路径: {as_path}")
        
        if i >= 4: break
    print("\n✅ Python 接口已打通，底层驱动运行正常！")
except Exception as e:
    print(f"\n❌ 运行出错: {e}")