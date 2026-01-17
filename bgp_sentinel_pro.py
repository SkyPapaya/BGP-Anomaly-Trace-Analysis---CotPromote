import pybgpstream
from pyod.models.iforest import IForest
from openai import AsyncOpenAI  # 使用异步客户端
import numpy as np
import collections
import asyncio
import aiofiles  # 请确保 pip install aiofiles
import json
import os
from datetime import datetime, timezone

# --- 核心配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"
current_time = datetime.now(timezone.utc)
SAVE_FILE = "rca_results_async_" + current_time.strftime("%Y-%m-%d_%H:%M:%S")+".jsonl" # 使用 JSONL 格式更适合并发写入

# 实验参数
TARGET_AS = "13414"           # Twitter 受害者
HIJACKER_AS = "12389"         # 劫持者
WARMUP_COUNT = 100000          # IForest 预热样本数            
SUPPRESSION_INTERVAL = 300    
MAX_CONCURRENT_DIAGNOSIS = 5  # 最大并发 AI 诊断数
SCORE_THRESHOLD = 0.2         # 算法分触发阈值

class FeatureExtractor:
    def __init__(self):
        self.prefix_history = {}
        self.update_counts = collections.defaultdict(int)

    def extract(self, elem):
        prefix = elem.fields.get("prefix")
        as_path = elem.fields.get("as-path", "").split(" ")
        # 简单计算编辑距离（迭代版）
        def dist(s1, s2):
            if len(s1) < len(s2): return dist(s2, s1)
            if not s2: return len(s1)
            prev = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                curr = [i + 1]
                for j, c2 in enumerate(s2):
                    curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
                prev = curr
            return prev[-1]

        f1_len = len(as_path)
        h = self.prefix_history.get(prefix, [])
        f2_dist = dist(as_path, h) if h else 0
        self.prefix_history[prefix] = as_path
        self.update_counts[prefix] += 1
        return [f1_len, f2_dist, len(elem.fields.get("communities", [])), self.update_counts[prefix]]

class BGPAnomalySentinelAsync:
    def __init__(self, start_time, end_time):
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.clf = IForest(contamination=0.05)
        self.fe = FeatureExtractor()
        self.start_time = start_time
        self.end_time = end_time
        
        self.sem = asyncio.Semaphore(MAX_CONCURRENT_DIAGNOSIS)
        self.last_alerts = {}
        self.is_trained = False
        self.feature_buffer = []
        self.last_progress_print = 0

    async def save_result_async(self, data):
        """异步追加写入结果"""
        async with aiofiles.open(SAVE_FILE, mode='a', encoding='utf-8') as f:
            line = json.dumps(data, ensure_ascii=False)
            await f.write(line + "\n")

    async def run_diagnosis_task(self, alert_context):
        """异步诊断任务：由信号量控制并发"""
        async with self.sem:
            utc_str = datetime.fromtimestamp(alert_context['timestamp'], tz=timezone.utc).strftime('%H:%M:%S')
            print(f"\n[AI 任务启动] 正在诊断 {utc_str} | 前缀: {alert_context['prefix']}")
            
            prompt = f"作为BGP专家，分析此异常。证据：{alert_context}。步骤：1.识别线索 2.推理原因 3.总结。"
            
            try:
                # 异步调用 DeepSeek
                completion = await self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[{"role": "user", "content": prompt}],
                    timeout=60
                )
                report = completion.choices[0].message.content
                
                # 构造最终存储结构
                final_data = {
                    "event_time_utc": datetime.fromtimestamp(alert_context['timestamp'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    "evidence": alert_context,
                    "ai_diagnosis": report
                }
                await self.save_result_async(final_data)
                print(f"✅ 诊断成功: {alert_context['prefix']} (已存入 {SAVE_FILE})")
                
            except Exception as e:
                print(f"❌ AI 诊断异常 [{alert_context['prefix']}]: {e}")

    async def main_loop(self):
        # 初始化数据流
        stream = pybgpstream.BGPStream(
            from_time=self.start_time, until_time=self.end_time,
            collectors=["rrc21"], record_type="updates"
        )

        print(f"[*] 异步引擎启动: {self.start_time} --> {self.end_time} (UTC)")
        active_tasks = []

        # 由于 pybgpstream 的迭代是同步阻塞的，我们通过 asyncio 处理并发任务
        for elem in stream:
            # 1. 进度打印
            if elem.time - self.last_progress_print >= 60:
                current_utc = datetime.fromtimestamp(elem.time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                # 统计当前排队中的任务
                active_tasks = [t for t in active_tasks if not t.done()]
                print(f"\r>>> 进度: [{current_utc}] | 待处理AI任务: {len(active_tasks)}", end="")
                self.last_progress_print = elem.time

            if elem.type != "A": continue
            
            # 2. 特征与模型
            features = self.fe.extract(elem)
            if not self.is_trained:
                self.feature_buffer.append(features)
                if len(self.feature_buffer) >= WARMUP_COUNT:
                    self.clf.fit(self.feature_buffer)
                    self.is_trained = True
                    print(f"\n✅ IForest 训练完成。")
                continue

            # 3. 判定逻辑
            score = -self.clf.decision_function(np.array([features]))[0]
            is_anomaly = self.clf.predict(np.array([features]))[0] == 1
            as_path_str = elem.fields.get("as-path", "")
            is_hijack = (HIJACKER_AS in as_path_str) or (as_path_str and as_path_str.split(" ")[-1] != TARGET_AS)

            # 4. 触发异步任务
            if is_hijack and (is_anomaly and score > SCORE_THRESHOLD):
                prefix = elem.fields.get("prefix")
                # 逻辑时间抑制
                if prefix not in self.last_alerts or (elem.time - self.last_alerts[prefix] > SUPPRESSION_INTERVAL):
                    self.last_alerts[prefix] = elem.time
                    
                    alert_context = {
                        "prefix": prefix,
                        "as_path": as_path_str,
                        "anomaly_score": round(float(score), 4),
                        "is_origin_mismatch": is_hijack,
                        "timestamp": elem.time
                    }
                    
                    # 创建异步诊断任务，不阻塞，直接进入下一个循环
                    new_task = asyncio.create_task(self.run_diagnosis_task(alert_context))
                    active_tasks.append(new_task)

            # 允许协程切换，处理后台任务
            if len(active_tasks) > 20: 
                await asyncio.sleep(0.01)

        # 数据流跑完后，等待所有残余任务完成
        if active_tasks:
            print(f"\n[*] 扫描完毕，正在等待最后 {len(active_tasks)} 条 AI 诊断完成...")
            await asyncio.gather(*active_tasks)
        print("\n[*] 所有任务执行结束。")

if __name__ == "__main__":
    sentinel = BGPAnomalySentinelAsync(
        start_time="2022-03-28 13:30:00",
        end_time="2022-03-28 14:10:00"
    )
    asyncio.run(sentinel.main_loop())