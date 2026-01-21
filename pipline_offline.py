import pybgpstream
from datetime import datetime
import asyncio
import os
import glob
import numpy as np
from tqdm import tqdm
from sklearn.ensemble import IsolationForest
from bgp_agent import BGPAgent

# --- 配置 ---
MAX_CONCURRENT_WORKERS = 5  # 并发数 (建议 3-5，防止 DeepSeek/RIPEstat 限流)
QUEUE_SIZE = 10          # 队列缓冲区大小

# --- 资产白名单 ---
ASSET_BASELINE = {
    "104.244.42.0/24": "13414",  # Twitter
    "8.8.8.0/24": "15169",       # Google
    "208.65.153.0/24": "36561"   # YouTube
}

class AnomalyDetector:
    """L2: IForest 异常检测器 (保持不变)"""
    def __init__(self):
        self.history = {}
        self.clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        self.train_data = []
        self.is_fitted = False

    def update_history(self, prefix, origin, as_path):
        if prefix not in self.history:
            self.history[prefix] = {'origins': set(), 'path_lens': []}
        self.history[prefix]['origins'].add(origin)
        self.history[prefix]['path_lens'].append(len(as_path.split()))

    def extract_features(self, prefix, origin, as_path):
        path_len = len(as_path.split())
        if prefix not in self.history:
            return [1, path_len, 0.0]
        record = self.history[prefix]
        is_new_origin = 1 if origin not in record['origins'] else 0
        avg_len = np.mean(record['path_lens'])
        len_diff = abs(path_len - avg_len)
        return [is_new_origin, path_len, len_diff]

    def check(self, prefix, origin, as_path):
        features = self.extract_features(prefix, origin, as_path)
        if not self.is_fitted:
            self.train_data.append(features)
            if len(self.train_data) > 50000:
                self.clf.fit(self.train_data)
                self.is_fitted = True
                tqdm.write("\n[ML] IForest 模型已训练完毕，开始介入...")
            return 1 
        prediction = self.clf.predict([features])[0]
        self.update_history(prefix, origin, as_path)
        return prediction

class BGPStreamPipeline:
    def __init__(self):
        self.agent = BGPAgent()
        self.detector = AnomalyDetector()
        self.queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        print(f"🤖 系统初始化: 启用 {MAX_CONCURRENT_WORKERS} 个并发 AI 。")

    def _extract_origin(self, as_path):
        if not as_path: return None
        return as_path.split(" ")[-1]

    def _construct_alert_context(self, elem, origin_as):
        return {
            "prefix": elem.fields['prefix'],
            "as_path": elem.fields['as-path'],
            "timestamp": int(elem.time),
            "detected_origin": origin_as,
            "expected_origin": ASSET_BASELINE.get(elem.fields['prefix'], "UNKNOWN"),
        }

    async def worker(self, worker_id):
        """
        消费者 Worker: 从队列取任务 -> 跑 AI -> 存报告
        """
        while True:
            # 从队列获取任务 (如果没有任务会在这里等待)
            task_data = await self.queue.get()
            
            alert_context = task_data['context']
            reason = task_data['reason']

            tqdm.write(f"⚡ [Worker-{worker_id}] 启动诊断: {alert_context['prefix']} ({reason})")

            try:
                # 调用 Agent (这是最耗时的步骤)
                # verbose=False 因为多线程打印会乱，我们只看 worker 的日志
                await self.agent.diagnose(alert_context, verbose=False)
                tqdm.write(f"✅ [Worker-{worker_id}] 诊断完成: {alert_context['prefix']}")
            except Exception as e:
                tqdm.write(f"❌ [Worker-{worker_id}] 任务失败: {e}")
            finally:
                # 标记该任务已完成
                self.queue.task_done()

    async def run_offline_replay(self, file_pattern):
        files = sorted(glob.glob(file_pattern))
        if not files: return

        # 1. 启动并发 Workers
        workers = []
        for i in range(MAX_CONCURRENT_WORKERS):
            w = asyncio.create_task(self.worker(i))
            workers.append(w)

        print(f"\n📂 开始并发处理 {len(files)} 个文件...")

        # 2. 生产者循环 (读取文件)
        for file_path in files:
            abs_path = os.path.abspath(file_path)
            file_name = os.path.basename(file_path)
            tqdm.write(f"\n📄 [加载] {file_name}")
            
            stream = pybgpstream.BGPStream(data_interface="singlefile")
            stream.set_data_interface_option("singlefile", "upd-file", abs_path)
            
            # 使用 tqdm 显示读取进度
            pbar = tqdm(stream, desc="过滤流数据", unit="pkt")
            
            for elem in pbar:
                if elem.type != "A": continue
                
                prefix = elem.fields['prefix']
                as_path = elem.fields['as-path']
                origin_as = self._extract_origin(as_path)
                
                # --- 过滤逻辑 (L1 + L2) ---
                hard_alert = False
                if prefix in ASSET_BASELINE and origin_as != ASSET_BASELINE[prefix]:
                    hard_alert = True
                
                ml_score = 1
                if not hard_alert:
                    ml_score = self.detector.check(prefix, origin_as, as_path)

                # --- 触发入队 ---
                if hard_alert or (ml_score == -1 and "12389" in as_path):
                    reason = "基准规则报警" if hard_alert else "IForest异常+嫌疑人"
                    
                    alert_context = self._construct_alert_context(elem, origin_as)
                    
                    # 构造任务包
                    task = {
                        'context': alert_context,
                        'reason': reason
                    }
                    
                    # 将任务放入队列 (如果队列满了，这里会暂停读取，等待 Worker 消费)
                    # 这就是"背压" (Backpressure) 机制，防止内存爆掉
                    await self.queue.put(task)
                    
                    tqdm.write(f"📥 [入队] 发现异常 ({reason}) -> 队列长度: {self.queue.qsize()}")

        # 3. 等待所有任务完成
        tqdm.write("\n⏳ 文件读取完毕，等待 AI Workers 处理剩余任务...")
        await self.queue.join() # 阻塞直到队列清空
        
        # 4. 取消 Workers
        for w in workers:
            w.cancel()
        
        print("\n🎉 所有并发任务已完成！")

if __name__ == "__main__":
    pipeline = BGPStreamPipeline()
    local_files = "/home/skypapaya/code/BGP-Anomaly-Trace-Analysis---CotPromote/data/updates*.gz"
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(pipeline.run_offline_replay(local_files))