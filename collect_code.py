import os

def collect_code(root_dir, output_file):
    # 定义需要收集的文件后缀
    include_extensions = ('.py', '.sh', '.cpp', '.h', '.yaml', '.yml', '.json', '.md')
    # 定义需要忽略的文件夹
    exclude_dirs = {'.git', '__pycache__', '.vscode', 'venv', 'node_modules', 'data', 'mrt_data'}

    with open(output_file, 'w', encoding='utf-8') as f_out:
        for root, dirs, files in os.walk(root_dir):
            # 排除忽略目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith(include_extensions):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, root_dir)
                    
                    f_out.write(f"\n{'='*50}\n")
                    f_out.write(f"FILE: {relative_path}\n")
                    f_out.write(f"{'='*50}\n\n")
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f_in:
                            f_out.write(f_in.read())
                    except Exception as e:
                        f_out.write(f"Error reading file: {e}\n")
                    f_out.write("\n")

if __name__ == "__main__":
    # 在当前目录下生成全量代码文档
    collect_code('.', 'project_context.txt')
    print("代码收集完成！请查看 project_context.txt")