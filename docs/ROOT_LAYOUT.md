# 项目根目录说明

根目录保留项目入口、构建文件与按职责划分的一级目录：`README.md`、`QA.md`、`LICENSE`、`pom.xml`、Maven Wrapper、`src/`、`docs/`、`data/`、`analysis/`、`research/`、`reverse-engineering/`、`reports/`、`scripts/`、`frida_scripts/`、`tools/` 与 `artifacts/`。

## 已版本化的内容

- `src/`：Spring Boot 服务与测试代码。
- `docs/`：稳定、可公开的使用与维护文档。
- 项目根目录的 Maven Wrapper、`pom.xml` 与基本项目文档。

## 本地研究工作区

以下目录按用途保留在工作区，但默认不纳入版本控制：

- `data/` 与 `artifacts/`：抓包、设备资料、日志、运行结果与备份。
- `analysis/`：静态分析产物与工具输出。
- `research/`、`reverse-engineering/`、`frida_scripts/`、`scripts/` 与 `tools/`：尚未审查的实验脚本、Hook、历史报告与辅助工具。
- `reports/`：历史报告；稳定结论应整理进 `docs/`。

这些内容可能包含 IPA/HAR、解包的第三方应用、设备标识、cookie、token 或仅适用于本机的路径。需要提交时，应先去除这些数据，并将可公开、可复现的最小内容放进 `docs/`、`src/test/resources/` 或经过评审的源码目录。

## 提交规则

`.gitignore` 排除了缓存、Finder 元数据、Python bytecode、备份文件、日志、IPA/HAR、解包应用、设备注册结果以及本地研究目录。脚本仍应从项目根目录执行，以保持它们对相对路径的既有假设。
