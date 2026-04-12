import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { COLORS } from "./theme";

const box = (label: string, sub?: string) => (
  <div
    style={{
      padding: "14px 18px",
      borderRadius: 12,
      border: `1px solid ${COLORS.border}`,
      background: "rgba(11, 15, 26, 0.75)",
      fontSize: 14,
      fontWeight: 600,
      color: COLORS.text,
      minWidth: 160,
      textAlign: "center",
    }}
  >
    {label}
    {sub && (
      <div style={{ fontSize: 11, color: COLORS.textMuted, marginTop: 6, fontWeight: 400 }}>
        {sub}
      </div>
    )}
  </div>
);

export const DataFlow: React.FC = () => {
  const frame = useCurrentFrame();
  const p = interpolate(frame % 90, [0, 45, 90], [0, 1, 0], { extrapolateRight: "clamp" });

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
          top: 32,
          left: 48,
          fontSize: 24,
          fontWeight: 700,
          color: COLORS.accent,
        }}
      >
        数据流：Markdown → 派生物 → 挂载
      </div>

      <div
        style={{
          position: "absolute",
          top: 120,
          left: 60,
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-start",
          gap: 20,
        }}
      >
        {box("Markdown 正文", "真源")}
        <div
          style={{
            marginLeft: 80,
            fontSize: 22,
            color: COLORS.accent,
            opacity: 0.5 + p * 0.5,
          }}
        >
          ↓
        </div>
        <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
          {box("creating-blog-web-ppt", "单文件 deck.html")}
          <span style={{ color: COLORS.textMuted }}>+</span>
          {box("front matter `ppt`", "开关")}
        </div>
        <div style={{ marginLeft: 80, fontSize: 22, color: COLORS.magenta, opacity: 0.5 + p * 0.5 }}>
          ↓
        </div>
        {box("Jekyll 布局 + scifi.js", "分栏 / iframe / 探测")}
      </div>

      <div
        style={{
          position: "absolute",
          top: 140,
          right: 80,
          width: 320,
          padding: 18,
          borderRadius: 14,
          border: `1px dashed ${COLORS.magenta}`,
          background: "rgba(148, 168, 232, 0.06)",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 700, color: COLORS.magenta, marginBottom: 10 }}>
          并行线（不经 ppt）
        </div>
        <div style={{ fontSize: 12, color: COLORS.textMuted, lineHeight: 1.55 }}>
          Remotion → <code style={{ color: COLORS.text }}>pic/</code> 下 mp4/gif
          <br />
          正文里 <code style={{ color: COLORS.text }}>&lt;video&gt;</code> 或图片引用
        </div>
      </div>
    </AbsoluteFill>
  );
};
