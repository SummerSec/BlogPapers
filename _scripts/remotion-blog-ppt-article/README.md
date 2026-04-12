# remotion-blog-ppt-article

博文配套 Remotion 示意（与 [`remotion-blog-motion-assets`](../../.claude/skills/remotion-blog-motion-assets/SKILL.md) 对齐）。

## 画布

`src/theme.ts`：`W`×`H` = **1280×720**，`fps` = **30**。GIF 导出时 **`GIFW` 须与 `W` 一致（1280）**。

## 常用命令

```bash
cd _scripts/remotion-blog-ppt-article
npm install
npm run dev
```

单条 MP4：

```bash
npx remotion render src/index.ts dual-carrier --codec=h264 --crf=16 ../../2026/pic/blog-ppt-remotion/dual-carrier.mp4
```

## 《三种时间》一文配套 composition

| id | 说明 |
|----|------|
| `dual-carrier` | 深读 / 扫读 / 听讲 三种时间 |
| `three-paths-friction` | 真源后的三条路径与摩擦 |
| `same-origin-layers` | 借 token、不搬整站壳 |
| `path-strategy` | `ppt` 默认同名 vs `-ppt` |
| `reading-modes` | 分栏 / 仅文 / 仅 PPT / 独立打开 |
| `data-flow` | Markdown → deck / Jekyll / Remotion 并行 |

批量渲染后可按需用 `ffmpeg` 两阶段转 GIF（见下文）。

### Windows：MP4 → GIF（`GIFW` = 1280）

先确保已安装 `ffmpeg`，且 `dual-carrier.mp4` 等已渲染到 `2026/pic/blog-ppt-remotion/`。

```powershell
$dir = Resolve-Path "../../2026/pic/blog-ppt-remotion"
$GIFW = 1280
$ids = "dual-carrier","three-paths-friction","same-origin-layers","path-strategy","reading-modes","data-flow"
foreach ($id in $ids) {
  $mp4 = Join-Path $dir "$id.mp4"
  $gif = Join-Path $dir "$id.gif"
  ffmpeg -y -i $mp4 -vf "fps=12,scale=${GIFW}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=256:reserve_transparent=1[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3" $gif
}
```

## 一键

```bash
npm run render:three-times
npm run gif:three-times
```

第二条用子工程内 `ffmpeg-static` 做两阶段 palette，**`GIFW` = 画布宽 1280**，无需本机安装 `ffmpeg`。若你本机已有 `ffmpeg`，也可用 README 前文 PowerShell 自行转换。
