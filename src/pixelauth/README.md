# 像素编辑证明实验

这是本地新增的实验实现，不是原仓库 Groth16 电路，也不是 PhotoProof 论文中递归 PCD 的完整复现。

目标：验证者拿到最终图片、来源证书和各步证明，能够检查图片经过的编辑是否符合来源方授权。验证者不需要原图和中间图片。允许操作是整数坐标裁剪、最近邻缩小、90 度倍数旋转；顺序固定为裁剪、缩小、旋转。

## 实现

每个 RGB8 像素编码为一个 24 位整数。BLS12-381 G1 上的向量 Pedersen 承诺为：

`C = sum(v_i * G_i) + r * H`。

各个 `G_i` 和 `H` 用不同输入做 hash-to-curve 生成，不能用具有已知离散对数关系的生成元代替。Ed25519 签名绑定原图承诺、尺寸、操作权限和生成元缓存摘要。验证方必须从可信渠道取得 `authority.json`，不能接受编辑者自行替换信任根。

一次操作确定输出到输入的公开索引映射 `m(j)`。证明者同时证明以下两个承诺使用相同的一组输入像素：

- 输入承诺：`C_s = sum(v_i * G_i) + r_s * H`
- 输出承诺：`C_o = sum(v_m(j) * G_j) + r_o * H`

使用广义 Schnorr 协议：独立随机掩码 `k_i, k_s, k_o` 形成两个 nonce 承诺，SHA-512 Fiat–Shamir 挑战 `c` 绑定证书、之前各步的摘要、本步操作和承诺，响应为 `z_i=k_i+c*v_i`，两个盲因子也作同样响应。验证者检查两条群等式。最终图片还必须通过自身像素与最终承诺的对应检查。

第二个编辑者只需上一轮的图片、最终承诺的 opening 和已有证明，即可创建下一步证明。新包保留全部已有证明，不包含之前的图片和 opening。它是逐步证明组成的显式链，长度随编辑次数增长，没有递归压缩。

最近邻取样规则为 `floor(u * crop_width / resize_width)`、`floor(v * crop_height / resize_height)`，旋转映射见 pixels.go。公开信息包括原图尺寸、操作参数、编辑次数和最终图像。隐私目标是隐藏最终图像没有披露的原图像素；不是隐藏这些公开信息。

## 安全边界

这是新编写的研究原型。Schnorr 的诚实验证者零知识性质和随机预言机模型下的 Fiat–Shamir 转换是设计依据；组合协议尚未经过独立审计或完整形式化安全证明，不能据测试结果宣称生产级安全。承诺绑定依赖离散对数困难及独立生成元，签名依赖可信签发方。实验签名由本机临时生成，未接入真实相机或机构；证明不了照片拍摄的时间、地点或内容真实性。

原始图像以解码后的不透明 RGB8 像素为准，排除 EXIF 等元数据。输出存 PNG，重新压缩 JPEG 会改变像素，不能直接通过。仅支持最近邻缩小，不支持双线性/双三次缩放、任意角度旋转、滤镜和修图。最大 200 万输入像素、64 步编辑。

生成元缓存由可信配置的 SHA256 固定。仅此缓存的读取省去重复子群检查；外部证明点仍做子群检查。信任配置本身必须受保护，不能把编辑包内任意配置当作权威。

证明大小每步为 `168 + 32 * 输入像素数` 字节。没有可信设置的秘密废料，但公开生成元缓存较大：`4 + 96 * 原图像素数` 字节。验证成本和包大小都随输入像素数、步骤数增长，和简洁 SNARK 的性能不同。

## 运行

在 src 目录：

```sh
go run ./cmd/pixelproof -mode init -workspace ../experiment-results/pixel-auth -input ../1.JPG
go run ./cmd/pixelproof -mode edit -workspace ../experiment-results/pixel-auth -input ../1.JPG -out ../experiment-results/pixel-auth/edit-a -x 137 -y 83 -width 901 -height 617 -resize-width 451 -resize-height 309 -rotate 90
go run ./cmd/pixelproof -mode edit -trusted ../experiment-results/pixel-auth/trusted -prior ../experiment-results/pixel-auth/edit-a -out ../experiment-results/pixel-auth/edit-b -x 17 -y 29 -width 271 -height 397 -resize-width 181 -resize-height 265 -rotate 270
go run ./cmd/pixelproof -mode verify -trusted ../experiment-results/pixel-auth/trusted -bundle ../experiment-results/pixel-auth/edit-b
go test ./pixelauth ./cmd/pixelproof
PHOTOPROOF_PIXEL_WORKSPACE="$PWD/../experiment-results/pixel-auth" go test ./cmd/pixelproof -run TestRealPhotoChain -count=1 -v
```

init 和 edit 拒绝覆盖已有目录。`source-opening.bin` 是原图持有者的私有文件，不能发送给最终验证者。编辑包的 `manifest.json` 只发布当前图片的 opening。后续编辑不再需要 workspace 参数或原图私有文件。
