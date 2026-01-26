#稳定性分析
# tools/stability.py
import collections

class StabilityAnalyzer:
    def __init__(self):
        # 这个状态需要在内存中持久保存
        self.update_counts = collections.defaultdict(int)

    def update_state(self, prefix):
        self.update_counts[prefix] += 1

    def run(self, context):
        prefix = context.get('prefix')
        count = self.update_counts.get(prefix, 0)
        
        if count == 0:
            return "NEW: 监控期间首次出现该前缀，可能是新发起的攻击或新业务。"
        elif count > 10:
             return f"UNSTABLE: 高频震荡！检测到 {count} 次更新，可能是路由收敛或持续攻击。"
        
        return f"STABLE: 累计更新 {count} 次，频率正常。"