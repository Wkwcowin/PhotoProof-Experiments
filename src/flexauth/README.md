# 可选裁剪、旋转与连续编辑

本版本在 `cropauth` 的固定裁剪实验上继续扩展。原图只签名一次，编辑者之后可以选择不同位置和大小的裁剪，并旋转 90°、180°或 270°。后续编辑可以接着处理结果图，最终仍验证到最初签名的原图。

当前操作按分块边界执行；提供的照片采用 90×90 像素分块。这不是任意像素位置的裁剪，也不支持缩放或 JPEG 有损再压缩。

## 三个独立命令

以下从 `src` 目录运行。`-workspace` 和 `-out` 指定的新目录不能已存在，以保留已有实验记录。

### 1. 签名方初始化一次

```bash
go run ./cmd/photoedit -mode init \
  -workspace ../experiment-results/my-edit-study \
  -input ../1.JPG
```

这一步允许后续裁剪和直角旋转，不提前指定裁剪位置。可用 `-allow-crop=false` 或 `-allow-rotate=false` 禁止对应操作。签名方对原图像素摘要及这些权限一起签名。

生成的目录中，`trusted/` 是验证者需要预先信任的公钥、规则和验证密钥；`proving-key.bin` 和 `editor-data.json` 交给编辑者。后者是原图块摘要，不含原图像素，不能作为公开验证材料随意发送。演示中的签名私钥不保存。

### 2. 编辑者选择操作并生成证明

```bash
go run ./cmd/photoedit -mode edit \
  -workspace ../experiment-results/my-edit-study \
  -input ../1.JPG \
  -out ../experiment-results/my-edit-study/edit-a \
  -x 90 -y 90 -width 990 -height 630 -rotate 90
```

输出目录包含 `image.png`、`proof.bin` 和 `manifest.json`。其中没有原图、原图全部块摘要或证明密钥。

再次编辑时输入上一次的证明包即可，不需要原图文件：

```bash
go run ./cmd/photoedit -mode edit \
  -workspace ../experiment-results/my-edit-study \
  -prior ../experiment-results/my-edit-study/edit-a \
  -out ../experiment-results/my-edit-study/edit-b \
  -x 90 -y 180 -width 360 -height 450 -rotate 90
```

这里的裁剪坐标相对于收到的当前图片。程序先验证前一步，再把两次操作合成为相对于原图的一次裁剪和旋转，生成新的证明。编辑者仍需持有最初提供的辅助摘要及证明密钥。

### 3. 验证者独立检查

```bash
go run ./cmd/photoedit -mode verify \
  -trusted ../experiment-results/my-edit-study/trusted \
  -bundle ../experiment-results/my-edit-study/edit-b
```

可额外用 `-input 路径` 指定实际收到的图片。验证器从该图片重新计算公开输入，不接受编辑者提交的替代像素摘要。通过输出 `ACCEPT`；失败输出 `REJECT` 并以非零状态退出。

`-trusted` 必须由验证者通过可信渠道取得，不能让编辑者同时替换公钥、规则和验证密钥。实验中的签名由临时密钥完成，并不证明最初拍摄者身份。

## 证明具体检查什么

电路使用同一份原图摘要列表作为秘密输入。公开输入包含原图承诺、签名、公钥、操作权限、本次裁剪坐标和尺寸、旋转角度及结果图的摘要。

1. 检查签名对应原图承诺和权限。
2. 将裁剪坐标及尺寸限制为合法整数，检查范围没有超出原图。
3. 通过受约束的行列选择器，选出这次裁剪对应的原图块摘要。
4. 检查选出的摘要与结果图一致；未使用的输出位置必须为零。
5. 检查旋转角度为允许的直角旋转。

验证器先按公开角度将收到的图片逆向旋转，再计算 SHA-256 块摘要。逆向旋转只排列像素，不做插值；这一部分和 SHA-256 在电路外执行。电路检查认证后的摘要关系。摘要用两个 128 位数表示，原图的有序摘要及权限用 MiMC 承诺，签名为 EdDSA，证明为 Groth16 / BN254。

## 验证记录

完整照片的三个编辑结果使用了同一份原图签名和同一套参数，均通过独立验证。反向测试包括改一个像素、添加方块、替换图片、修改坐标和角度、破坏证明及继续编辑已被篡改的图片，均被拒绝。另有小图测试覆盖所有旋转组合、越界和负坐标、空裁剪、输出填充、签名权限及直接构造的非法电路见证。

运行普通测试：

```bash
go test ./flexauth -count=1 -v
```

验证本次保存的真实图片实验：

```bash
PHOTOPROOF_FLEX_WORKSPACE=/Users/wangkewen/Pictures/HBUT/code/PhotoProof/experiment-results/flex-auth \
  go test ./cmd/photoedit -run TestRealImageBundles -count=1 -v
```

## 还未完成的部分

- 任意像素位置裁剪：当前按分块对齐，默认是 90 像素。把完整照片改为逐像素电路会显著增大规模，需要先设计并测量更高效的认证结构。
- 缩放：需要先确定缩放算法和取整规则，再证明输出像素满足该算法；当前没有把缩放或有损压缩当作允许修改。
- 完整递归编辑证明：现在证明最终图片可以由原图按允许规则得到，不是在电路中递归验证每一份旧证明，也不证明编辑历史中的每一步确实发生过。
- 部署准备：尚未加入真实相机身份、长期密钥管理和独立密码学审查。Groth16 的本地 Setup 仍是可信预处理。

源图尺寸、裁剪位置、权限和原图承诺是公开的。原图被裁掉的像素不交给验证者。这里不声称隐藏所有元数据、阻止多个结果被关联，或判断照片内容是否真实。
