# GitHub 仓库与后续更新

项目内容已整理好，本地 Git 历史仍保留上游来源。原来的远程地址已从 origin 改名为 upstream，避免把新增实验误推到原作者仓库。

自己的仓库地址为 https://github.com/Wkwcowin/PhotoProof-Experiments ，origin 指向此仓库，upstream 保留原项目地址。后续在本项目目录更新：

```sh
git add .
git diff --cached --stat
git commit -m "Update photo authentication experiments"
git push
```

上传前查看暂存清单：应包含源码、报告、图片、日志和上游资料，不应包含 `.DS_Store`、`source-opening.bin`、`editor-data.json`、`generators.bin` 或 `runs/`。这些项目已写入 `.gitignore`，通过 Git 添加时会被排除。不要将整个本地文件夹直接拖到网页上传，否则可能绕过忽略规则。

实验用原图 `1.JPG` 随源码上传，以便复现。仓库初始设为私有，老师需要接受仓库访问邀请才能打开链接。若以后改为公开，先确认原图适合公开。来源与许可情况见 [UPSTREAM.md](../UPSTREAM.md)。

上传后，把仓库主页链接发给老师即可。首页包含实验结论、结果图片、对照测试和一条命令的复现方法。无需发送本地生成的大文件。
