# Encoding Guard

**中文** | [English](./README.md)

`encoding-guard` 是一个极简技能，核心目标是：**优先输出中文**，并通过最小编码策略避免中文乱码（mojibake）。

## 核心能力

1. 初始化最小策略文件
2. 在中文输出前解析输出编码

## 快速使用

```bash
python scripts/encoding_guard.py init-policy --root <repo>
python scripts/encoding_guard.py get-output-encoding --root <repo>
```

- 默认策略文件：`<repo>/.encoding-policy.json`
- 默认策略内容：

```json
{"encoding":"utf-8"}
```

## 行为准则

- 默认输出中文，除非用户明确要求其他语言。
- 不要把“切换英文”当作编码问题的规避手段。
- 若编码解析失败，回退到 `utf-8`，并继续中文输出。
