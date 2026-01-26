import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# --- 配置 ---
JSON_FILE = "scan_evidence.json"

def analyze_bgp_radar_data():
    print(f"[*] 正在读取分析文件: {JSON_FILE}...")
    
    try:
        with open(JSON_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] 错误: 无法读取文件，请确保雷达扫描已结束。详细错误: {e}")
        return

    if not data:
        print("[-] 错误: 文件内容为空。")
        return

    # 1. 转换为 DataFrame
    # 这里的 key 必须和你的 JSON 格式完全一致
    records = []
    for entry in data:
        as_path_list = entry['as_path'].split(" ") if entry['as_path'] else []
        records.append({
            'time': pd.to_datetime(entry['time']),
            'prefix': entry['prefix'],
            'score': entry['score'],
            'is_mismatch': 1 if entry['is_mismatch'] else 0,
            'is_hijack_path': 1 if entry['is_hijacker_in_path'] else 0,
            'origin_as': as_path_list[-1] if as_path_list else "Unknown"
        })
    
    df = pd.DataFrame(records)
    df = df.set_index('time')

    # 2. 按分钟重采样统计 (Resampling)
    # 统计每分钟：异常消息总数、平均分、起源不匹配总数、确认劫持路径总数
    stats_min = df.resample('1min').agg({
        'prefix': 'count',
        'score': 'max',
        'is_mismatch': 'sum',
        'is_hijack_path': 'sum'
    }).fillna(0)

    # 3. 打印核心实验指标 (用于论文数据章节)
    print("\n" + "="*30)
    print("      BGP 实验统计摘要")
    print("="*30)
    print(f"数据总区间: {df.index.min()} 至 {df.index.max()}")
    print(f"检测到的疑似更新总数: {len(df)}")
    print(f"触发起源不匹配(Mismatch)次数: {df['is_mismatch'].sum()}")
    print(f"路径中包含目标劫持者(AS12389)次数: {df['is_hijack_path'].sum()}")
    print(f"出现频率最高的疑似起源AS: \n{df['origin_as'].value_counts().head(5)}")
    print("="*30)

    # 4. 绘图：多维度趋势分析
    plt.figure(figsize=(14, 8))

    # 子图1：消息频率趋势 (展示劫持爆发规模)
    plt.subplot(3, 1, 1)
    plt.plot(stats_min.index, stats_min['prefix'], color='tab:red', linewidth=2, label='Total Anomalies')
    plt.fill_between(stats_min.index, stats_min['prefix'], color='tab:red', alpha=0.2)
    plt.title("BGP Anomaly Distribution (Time-Series Analysis)", fontsize=14)
    plt.ylabel("Updates / Min")
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend()

    # 子图2：起源不匹配与确认劫持对比
    plt.subplot(3, 1, 2)
    plt.bar(stats_min.index, stats_min['is_mismatch'], width=0.0005, color='orange', label='Origin Mismatch')
    plt.bar(stats_min.index, stats_min['is_hijack_path'], width=0.0005, color='black', label='Confirmed Hijacker in Path')
    plt.ylabel("Event Count")
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend()

    # 子图3：算法得分波动 (展示 IForest 的敏感度)
    plt.subplot(3, 1, 3)
    plt.plot(stats_min.index, stats_min['score'], color='tab:blue', label='Max Anomaly Score')
    plt.axhline(y=0.2, color='green', linestyle='--', alpha=0.5, label='Threshold (0.2)')
    plt.xlabel("Time (UTC)")
    plt.ylabel("IForest Score")
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend()

    plt.tight_layout()
    output_img = "bgp_radar_analysis.png"
    plt.savefig(output_img, dpi=300)
    print(f"\n[+] 分析图表已保存为: {output_img}")
    plt.show()

if __name__ == "__main__":
    analyze_bgp_radar_data()