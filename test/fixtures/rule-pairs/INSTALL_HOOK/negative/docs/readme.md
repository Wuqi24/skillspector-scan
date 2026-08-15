# INSTALL_HOOK negative fixture（安全文档示例）

本技能不包含安装钩子，以下仅为检测规则说明：

- 检测项：package.json 中的 "postinstall" 脚本
- 安全形态：postinstall 仅执行构建命令，如：
  "postinstall": "node scripts/build.js"

上述模式位于文档语境，命中应归参考发现，不计分、不进 TOP3。
