import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { COLORS } from "./theme";

const paths = [
  { title: "传统 .pptx", pain: "版本脱嵌 · 二进制" },
  { title: "在线 slide", pain: "域名样式 ≠ 正文" },
  { title: "同目录网页 deck", pain: "无魔法同步 · 可审计" },
] as const;

export const ThreePathsFriction: React.FC = () => {
  const frame = useCurrentFrame();
  const t = (frame * 0.08) % (Math.PI * 2);

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
          color: COLORS.danger,
        }}
      >
        真源之后：三条路的摩擦
      </div>

      <div
        style={{
          position: "absolute",
          top: 120,
          left: 48,
          right: 48,
          display: "flex",
          gap: 24,
          height: 420,
        }}
      >
        {paths.map((p, i) => {
          const shake =
            i < 2
              ? Math.sin(t + i) * interpolate(frame % 90, [0, 45, 90], [0, 4, 0])
              : 0;
          const good = i === 2;
          const border = good ? COLORS.green : COLORS.danger;
          return (
            <div
              key={p.title}
              style={{
                flex: 1,
                transform: `translateX(${shake}px)`,
                borderRadius: 16,
                border: `2px solid ${border}`,
                background: good
                  ? "rgba(125, 215, 154, 0.08)"
                  : "rgba(224, 160, 80, 0.06)",
                padding: 22,
                display: "flex",
                flexDirection: "column",
                gap: 16,
              }}
            >
              <div style={{ fontSize: 18, fontWeight: 700, color: COLORS.text }}>
                {p.title}
              </div>
              <div style={{ fontSize: 14, color: COLORS.textMuted, lineHeight: 1.55 }}>
                {p.pain}
              </div>
              {good && (
                <div style={{ marginTop: "auto", fontSize: 13, color: COLORS.green }}>
                  与博客同管道归档
                </div>
              )}
            </div>
          );
        })}
      </div>
    </AbsoluteFill>
  );
};
