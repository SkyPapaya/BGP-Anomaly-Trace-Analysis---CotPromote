import os

# ================= 配置区域 =================

# 1. 输出文件名
OUTPUT_FILE = "project_context.txt"

# 2. 要忽略的文件夹 (完全匹配)
# 结合你的项目情况，我已预设了常见不需要的目录
IGNORE_DIRS = {
    '.git', '.idea', '.vscode', '__pycache__', 'venv', 'env', 
    'node_modules', 'dist', 'build',
    'rag_db', 'rag_db_new', 'rag_db_debug', # 忽略 RAG 数据库
    'data',   # 忽略原始数据文件夹
    'report', # 忽略生成的报告文件夹
    'lib',    # 如果有编译好的库文件也忽略
    '.pyc'
}

# 3. 要忽略的具体文件名 (完全匹配)
IGNORE_FILES = {
    '.DS_Store', 'poetry.lock', 'package-lock.json', 
    OUTPUT_FILE, __file__ # 忽略输出文件和脚本本身
}

# 4. 只收集这些后缀的文件 (白名单模式，防止读取到 .gz, .exe 等二进制文件)
ALLOWED_EXTENSIONS = {
    '.py',   # Python
    '.java', # Java
    '.js', '.vue', '.html', '.css', # 前端
    '.md', '.txt', # 文档
    '.json', '.yaml', '.yml', '.xml', # 配置文件
    '.sh', '.bat' # 脚本
}

# ===========================================

def collect_code():
    print(f"🚀 开始扫描当前目录: {os.getcwd()}")
    print(f"📄 输出文件将保存为: {OUTPUT_FILE}")
    
    count = 0
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as outfile:
        # 写入头部信息
        outfile.write(f"Project Context Collection\n")
        outfile.write(f"==========================\n\n")

        # os.walk 遍历目录
        for root, dirs, files in os.walk('.'):
            # 1. 修改 dirs 列表，实现原地剪枝 (忽略文件夹)
            # 这一步非常重要，可以阻止脚本进入 .git 或 data 等巨大目录
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                # 2. 检查文件名忽略列表
                if file in IGNORE_FILES:
                    continue

                # 3. 检查文件后缀
                _, ext = os.path.splitext(file)
                if ext.lower() not in ALLOWED_EXTENSIONS:
                    continue

                # 4. 读取并写入
                file_path = os.path.join(root, file)
                
                # 为了显示好看，把路径里的 ./ 去掉
                clean_path = file_path.replace('.\\', '').replace('./', '')
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as infile:
                        content = infile.read()
                        
                        # 写入文件分隔符，方便 AI 识别
                        outfile.write(f"\n{'='*50}\n")
                        outfile.write(f"FILE PATH: {clean_path}\n")
                        outfile.write(f"{'='*50}\n\n")
                        outfile.write(content)
                        outfile.write("\n")
                        
                        print(f"✅ 已添加: {clean_path}")
                        count += 1
                except Exception as e:
                    print(f"❌ 读取失败: {clean_path} ({e})")

    print(f"\n🎉 完成！共收集了 {count} 个文件。")
    print(f"👉 请打开 '{OUTPUT_FILE}' 全选复制发给我。")

if __name__ == "__main__":
    collect_code()