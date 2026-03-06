# BGP 异常测试案例库（分类存放）

本目录按异常类型分类存放测试案例，每类固定 10 个。

- `hijack/`：前缀劫持类（10）
- `leak/`：路由泄露类（10）
- `forgery/`：路径伪造类（10）

每个类型目录包含：

- `real.json`：真实历史事件案例
- `synthetic.json`：模拟补充案例（带 `simulation_reason`）
- `cases_10.json`：合并后的该类型 10 个案例
- `../index.json`：全库汇总（每类 real/synthetic 数量与补充原因）

字段约定：

- `source_type`: `real` / `synthetic`
- `event_type`: `HIJACK` / `LEAK` / `FORGERY`
- `event`: 真实事件输入（用于 Step1 抓取）
- `context`: 模拟事件上下文（可直接喂 `diagnose_batch`）
- `context.updates`: 支持 1 条或多条 update 消息（推荐保留多观测点/多时刻更新以便归因）
- `simulation_reason`: 模拟补充的原因说明（仅 synthetic）

说明：

- 真实事件优先收集；若公开可验证真值不足，使用模拟案例补齐到每类 10 个。
- `FORGERY` 类型公开“可核验且带明确攻击者真值”的真实事件较少，因此主要使用模拟补充。

当前统计（2026-03-06）：

- `HIJACK`: real=6, synthetic=4, total=10
- `LEAK`: real=5, synthetic=5, total=10
- `FORGERY`: real=0, synthetic=10, total=10
