import subprocess
import os
import time
from flask import Flask, request, jsonify
from openai import OpenAI

app = Flask(__name__)

# 1. 配置路径与 API
BGPALERTER_PATH = "/home/skypapaya/code/BGP-Anomaly-Trace-Analysis---CotPromote/bgpalerter/bgpalerter-linux-x64"
client = OpenAI(api_key="sk-9944c48494394db6b8bc31b40f8a710f", base_url="https://api.deepseek.com")

def start_bgpalerter():
    """
    仿照 RCAgent 的工具调用逻辑，自动启动采集专家工具 [cite: 143
    """
    print(f"正在启动 bgpalerter 监测引擎...")
    # 获取二进制文件所在目录，确保它能找到 config.yml
    working_dir = os.path.dirname(BGPALERTER_PATH)
    
    # 以后台进程方式启动
    process = subprocess.Popen(
        [BGPALERTER_PATH],
        cwd=working_dir, 
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print(f"bgpalerter 已在后台启动 (PID: {process.pid})")
    return process

def generate_rca_report(alert_data):
    """
    LogSage CoT 诊断逻辑：提炼线索、推理、总结 [cite: 692, 693]
    """
    prompt = f"任务：作为 BGP 专家，分析以下异常告警。\n原始数据：{alert_data}\n" \
             "请执行以下步骤：\n1. 识别线索(ASN/Prefix/Path)\n2. 推理原因\n3. 生成总结。"
    
    try:
        completion = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "你是一个资深的 BGP 网络协议分析专家。"},
                {"role": "user", "content": prompt}
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"API 诊断异常: {str(e)}"

@app.route('/webhook', methods=['POST'])
def webhook():
    alert = request.json
    print(f"--- 捕捉到 BGP 异常信号 ---")
    report = generate_rca_report(alert)
    print(f"\n[DeepSeek RCA 报告]\n{report}\n")
    return jsonify({"status": "received"}), 200

if __name__ == '__main__':
    # 第一步：启动 bgpalerter 采集器
    bgp_process = start_bgpalerter()
    
    # 第二步：启动 Flask 诊断中心
    try:
        app.run(host='0.0.0.0', port=5000)
    finally:
        # 当 Python 脚本停止时，确保也关闭 bgpalerter
        print("正在关闭监测引擎...")
        bgp_process.terminate()