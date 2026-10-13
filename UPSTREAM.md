# 来源与修改说明

本项目基于 https://github.com/drakstik/PhotoProof ，初始检出提交为 `777a9c92f2b7aab4ea9500345b85b01461bd3679`。

上游 README 保存在 [upstream/README.md](upstream/README.md)，上游课程报告和辅助 Go 模块也保存在 upstream 下。`src/main.go`、`src/image/` 及 Go 依赖文件来自上游；本地没有把这些代码改写为新增的像素证明方案。

本地新增：

- 真实照片对照测试 `src/real_photo_test.go`。
- 固定裁剪版本 `src/cropauth/` 和 `src/cmd/cropdemo/`。
- 分块裁剪、旋转与后续编辑版本 `src/flexauth/` 和 `src/cmd/photoedit/`。
- 像素承诺与逐步 Schnorr 证明版本 `src/pixelauth/` 和 `src/cmd/pixelproof/`。
- 实验图片、测量日志、报告、复现脚本和持续集成配置。

最新方案是一条新增实验路线，不能据此声称复现了原论文的全部协议或具有相同性能。上游代码、报告和论文的作者署名与本地实验作者署名分开保留。

初始检出的上游版本没有 LICENSE 文件。本仓库没有擅自为上游材料添加或变更开源许可；公开可访问不等于获得任意再许可权。Go 依赖适用各自的许可证。需要对外授权再分发时，应先核实相应材料的授权。
