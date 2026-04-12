import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { COLORS } from "./theme";

export const PathStrategy: React.FC = () => {
  const frame = useCurrentFrame();
  const left = interpolate(frame % 100, [0, 50, 100], [0.4, 1, 0.4]);
  const right = interpolate((frame + 50) % 100, [0, 50, 100], [0.4, 1, 0.4]);

  return (
    <AbsoluteFill
      style={{
        backgroundColor: COLORS.bg,
        fontFamily: "JetBrains Mono, Noto Sans SC, Microsoft YaHei UI, monospace",
        color: COLORS.text,
      }}
    >
      <div
        style={{
          position: "absolute",
          top: 36,
          left: 48,
          fontSize: 26,
          fontWeight: 700,
          color: COLORS.text,
        }}
      >
        `ppt` 路径：默认同名 vs <code style={{ color: COLORS.accent }}>-ppt</code> 显式
      </div>

      <div
        style={{
          position: "absolute",
          top: 140,
          left: 60,
          right: 60,
          display: "flex",
          gap: 40,
        }}
      >
        <div
          style={{
            flex: 1,
            borderRadius: 16,
            border: `2px solid rgba(148, 168, 232, ${0.35 + left * 0.5})`,
            padding: 22,
            background: "rgba(148, 168, 232, 0.06)",
          }}
        >
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 14, color: COLORS.magenta }}>
            A. 默认同名
          </div>
          <code style={{ fontSize: 13, color: COLORS.text }}>foo.md</code>
          <span style={{ color: COLORS.textMuted, margin: "0 8px" }}>+</span>
          <code style={{ fontSize: 13, color: COLORS.text }}>foo.html</code>
          <div style={{ marginTop: 16, fontSize: 13, color: COLORS.textMuted }}>
            可不写 <code style={{ color: COLORS.accent }}>ppt</code>，布局猜同 stem
          </div>
        </div>

        <div
          style={{
            flex: 1,
            borderRadius: 16,
            border: `2px solid rgba(92, 219, 207, ${0.35 + right * 0.5})`,
            padding: 22,
            background: "rgba(92, 219, 207, 0.06)",
          }}
        >
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 14, color: COLORS.accent }}>
            B. <code>-ppt</code> 后缀
          </div>
          <code style={{ fontSize: 13, color: COLORS.text }}>foo.md</code>
          <span style={{ color: COLORS.textMuted, margin: "0 8px" }}>+</span>
          <code style={{ fontSize: 12, color: COLORS.text }}>foo-ppt.html</code>
          <div style={{ marginTop: 16, fontSize: 13, color: COLORS.textMuted }}>
            front matter 写 <code style={{ color: COLORS.accent }}>ppt: ./foo-ppt.html</code>
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
