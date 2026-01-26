import pybgpstream
from pyod.models.iforest import IForest
import numpy as np
import collections
import json
from datetime import datetime, timezone

# --- 验证配置 ---
TARGET_AS = "13414"           # Twitter 受害者
HIJACKER_AS = "12389"         # 劫持者 (Rostelecom)
WARMUP_COUNT = 10000       # 预热样本
SCORE_THRESHOLD = 0.1         # 算法灵敏度阈值
SCAN_LOG = "scan_evidence.json"

class FeatureExtractor:
    def __init__(self):
        self.prefix_history = {}
        self.update_counts = collections.defaultdict(int)

    def extract(self, elem):
        prefix = elem.fields.get("prefix")
        as_path_str = elem.fields.get("as-path", "")
        as_path = as_path_str.split(" ") if as_path_str else []
        
        # 特征提取
        f1_len = len(as_path)
        h = self.prefix_history.get(prefix, [])
        f2_dist = self._dist(as_path, h) if h else 0
        self.prefix_history[prefix] = as_path
        f3_comm_cnt = len(elem.fields.get("communities", []))
        self.update_counts[prefix] += 1
        
        return [f1_len, f2_dist, f3_comm_cnt, self.update_counts[prefix]]

    def _dist(self, s1, s2):
        if len(s1) < len(s2): return self._dist(s2, s1)
        if not s2: return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
            prev = curr
        return prev[-1]

def run_radar_scan():
    extractor = FeatureExtractor()
    clf = IForest(contamination=0.05)
    
    stream = pybgpstream.BGPStream(
        from_time="2022-03-28 13:30:00",
        until_time="2022-03-28 14:10:00",
        collectors=["rrc21"],
        record_type="updates"
    )

    print(f"[*] 启动雷达扫描模式 (不调用 AI)...")
    evidence_list = []
    is_trained = False
    feature_buffer = []
    msg_count = 0
    anomaly_count = 0
    last_print_time = 0

    for elem in stream:
        msg_count += 1
        if elem.time - last_print_time >= 60:
            current_utc = datetime.fromtimestamp(elem.time, tz=timezone.utc).strftime('%H:%M:%S')
            print(f"\r>>> 进度: [{current_utc}] | 已扫描: {msg_count} | 已捕获异常: {anomaly_count}", end="")
            last_print_time = elem.time

        if elem.type != "A": continue
        
        features = extractor.extract(elem)
        
        if not is_trained:
            feature_buffer.append(features)
            if len(feature_buffer) >= WARMUP_COUNT:
                clf.fit(feature_buffer)
                is_trained = True
                print(f"\n✅ IForest 建模完成，开始实时打分...")
            continue

        # 算法打分
        score = -clf.decision_function(np.array([features]))[0]
        
        # 规则判定 (Origin 校验)
        as_path_str = elem.fields.get("as-path", "")
        as_path_list = as_path_str.split(" ")
        origin_as = as_path_list[-1] if as_path_list else ""
        
        # 核心判定：只要满足 Origin 异常 或者 算法分突破阈值
        is_origin_mismatch = (origin_as != TARGET_AS)
        is_algorithm_anomaly = (score > SCORE_THRESHOLD)

        if is_origin_mismatch or is_algorithm_anomaly:
            anomaly_count += 1
            evidence = {
                "time": datetime.fromtimestamp(elem.time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                "prefix": elem.fields.get("prefix"),
                "as_path": as_path_str,
                "score": round(float(score), 4),
                "is_mismatch": is_origin_mismatch,
                "is_hijacker_in_path": HIJACKER_AS in as_path_str
            }
            evidence_list.append(evidence)

    # 保存结果
    with open(SCAN_LOG, 'w', encoding='utf-8') as f:
        json.dump(evidence_list, f, indent=4)
    
    print(f"\n\n[*] 扫描结束！")
    print(f"[*] 总计扫描 Update 消息: {msg_count}")
    print(f"[*] 捕获疑似异常点: {anomaly_count}")
    print(f"[*] 详细证据已存入: {SCAN_LOG}")

if __name__ == "__main__":
    run_radar_scan()