# 独立验证目录

原始实测时，此目录只包含可信配置、公共参数、最终图片和两步证明，没有原图或中间图片。验证通过的记录见 [../isolated-verification.log](../isolated-verification.log)。

为避免上传重复的大文件，Git 不包含生成元缓存和二进制证明。要运行独立验证，请在仓库根目录执行 `bash scripts/reproduce.sh`，它会在新的 runs 结果目录中生成完整的 verification-only 文件夹。此处保留的 JSON 和图片用于查看当次实验，不与新生成的随机证明混用。
