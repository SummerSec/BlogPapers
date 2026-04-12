import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ffmpegPath = require("ffmpeg-static");
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const picDir = path.resolve(__dirname, "../../../2026/pic/blog-ppt-remotion");
const GIFW = 1280;

const ids = [
  "dual-carrier",
  "three-paths-friction",
  "same-origin-layers",
  "path-strategy",
  "reading-modes",
  "data-flow",
];

for (const id of ids) {
  const input = path.join(picDir, `${id}.mp4`);
  const output = path.join(picDir, `${id}.gif`);
  const vf = `fps=12,scale=${GIFW}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=256:reserve_transparent=1[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3`;
  const r = spawnSync(
    ffmpegPath,
    ["-y", "-i", input, "-vf", vf, output],
    { stdio: "inherit" },
  );
  if (r.status !== 0) {
    process.exit(r.status ?? 1);
  }
  console.log("OK", output);
}
