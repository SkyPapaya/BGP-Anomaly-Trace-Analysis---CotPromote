import pybgpstream
from datetime import datetime
import json
import asyncio
from tqdm import tqdm  # 引入进度条库
from bgp_agent import BGPAgent

# --- 资产白名单 (Baseline) ---，后续可能需要进行更新，建立自己的知识库
ASSET_BASELINE = {
    "104.244.42.0/24": "13414",  # Twitter
    "8.8.8.0/24": "15169",       # Google
    "208.65.153.0/24": "36561"   # YouTube
}

class BGPStreamPipeline:
    def __init__(self):
        self.agent = BGPAgent()
        print("🤖 AI Agent 已就绪。")

    def _extract_origin(self, as_path):
        if not as_path: return None
        parts = as_path.split(" ")
        return parts[-1]

#提取代码
    def _construct_alert_context(self, elem, origin_as):
        return {
            "prefix": elem.fields['prefix'],
            "as_path": elem.fields['as-path'],
            "timestamp": int(elem.time),
            "detected_origin": origin_as,
            "expected_origin": ASSET_BASELINE.get(elem.fields['prefix']),
            "collector": elem.collector,
            "peer_asn": elem.peer_asn
        }

    async def run_replay(self, start_time, end_time, target_prefix=None):
        print(f"\n🌊 初始化 BGPStream...")
        print(f"   时间窗口: {datetime.fromtimestamp(start_time)} -> {datetime.fromtimestamp(end_time)}")
        print(f"   采集器: rrc00 (RIPE NCC)")
        if target_prefix:
            print(f"   目标过滤器: {target_prefix}")

        # 1. 配置 BGPStream
        stream = pybgpstream.BGPStream(
            from_time=start_time,
            until_time=end_time,
            record_type="updates",
        )
        stream.add_filter("collector", "rrc00")
        
        # 注意：如果在这里加了 filter，BGPStream 底层会过滤掉不匹配的数据
        # 这会导致 Python 循环很久才收到一条数据，看起来像卡死
        # 为了演示进度条的流动感，建议在代码层过滤，或者只相信进度条的 elapsed time
        if target_prefix:
            stream.add_filter("prefix", target_prefix)

        print("\n⏳ 正在建立连接并下载 MRT 数据包，请耐心等待 (可能需要 15-30秒)...")
        print("   (如果长时间不动，说明正在下载数 GB 的历史归档，并未卡死)")

        # 2. 启动流式处理 (使用 tqdm 包裹)
        # unit='pkt' 表示单位是数据包
        # desc='Replaying' 左侧描述文字
        anomaly_count = 0
        
        # 将 stream 放入 tqdm 中
        for elem in tqdm(stream, desc="正在回放 BGP 更新", unit=" pkt"):
            # 只关心 'A' (Announcement)
            if elem.type != "A":
                continue

            prefix = elem.fields['prefix']
            
            # --- 代码层二次确认 (防止 BGPStream 过滤器漏网) ---
            if target_prefix and prefix != target_prefix:
                continue

            as_path = elem.fields['as-path']
            origin_as = self._extract_origin(as_path)

            # --- L2: 粗筛逻辑 ---
            if prefix in ASSET_BASELINE:
                expected_owner = ASSET_BASELINE[prefix]
                
                if origin_as != expected_owner:
                    anomaly_count += 1
                    
                    # [关键] 使用 tqdm.write 避免打乱进度条
                    tqdm.write("\n" + "!"*60)
                    tqdm.write(f"🚨 [L2 警报] 发现异常源! ({datetime.fromtimestamp(int(elem.time))})")
                    tqdm.write(f"   Prefix: {prefix}")
                    tqdm.write(f"   Origin: AS{origin_as} (预期: AS{expected_owner})")
                    tqdm.write(f"   Path:   {as_path}")
                    tqdm.write("   >>> 唤醒 AI Agent 进行研判...")
                    tqdm.write("!"*60 + "\n")

                    # --- L3: AI 深度研判 ---
                    alert_context = self._construct_alert_context(elem, origin_as)
                    
                    # 调用 Agent (verbose=True 会打印很多字，可能会暂时打断进度条，这是正常的)
                    await self.agent.diagnose(alert_context, verbose=True)
                    
                    tqdm.write("\n✅ 研判结束，继续监听...\n")

    
if __name__ == "__main__":
    pipeline = BGPStreamPipeline()
    
    # Twitter 劫持时间窗口
    start_ts = "2022-03-28 13:30:00" 
    end_ts   = "2022-03-28 14:00:00" # 稍微拉长一点确保能扫到
    
    t_start = int(datetime.strptime(start_ts, "%Y-%m-%d %H:%M:%S").timestamp())
    t_end = int(datetime.strptime(end_ts, "%Y-%m-%d %H:%M:%S").timestamp())

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        pipeline.run_replay(t_start, t_end, target_prefix="104.244.42.0/24")
    )