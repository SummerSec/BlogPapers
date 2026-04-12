import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { COLORS } from "./theme";

const labels = ["深读 · 纵深", "扫读 · 结构", "听讲 · 横切"] as const;

export const DualCarrierThreeTimes: React.FC = () => {
  const frame = useCurrentFrame();
  const cycle = 50;
  const active = Math.floor((frame % (cycle * 3)) / cycle);

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
          right: 48,
          fontSize: 28,
          fontWeight: 700,
          color: COLORS.accent,
          letterSpacing: "0.02em",
        }}
      >
        一篇博文，三种时间
      </div>
      <div
        style={{
          position: "absolute",
          top: 88,
          left: 48,
          fontSize: 15,
          color: COLORS.textMuted,
        }}
      >
        同一套结论，三种履约：可追溯 / 一眼懂 / 跟节拍
      </div>

      <div
        style={{
          position: "absolute",
          left: 80,
          right: 80,
          top: 200,
          bottom: 120,
          display: "flex",
          gap: 28,
          alignItems: "stretch",
        }}
      >
        {labels.map((label, i) => {
          const on = active === i;
          const pulse = interpolate(
            frame % cycle,
            [0, cycle * 0.5, cycle],
            on ? [0.35, 1, 0.35] : [0.2, 0.25, 0.2],
            { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
          );
          return (
            <div
              key={label}
              style={{
                flex: 1,
                borderRadius: 16,
                border: `2px solid ${on ? COLORS.accent : COLORS.border}`,
                background: on
                  ? "rgba(92, 219, 207, 0.08)"
                  : "rgba(11, 15, 26, 0.6)",
                boxShadow: on
                  ? `0 0 40px rgba(92, 219, 207, ${pulse * 0.35})`
                  : "none",
                padding: 24,
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                alignItems: "center",
                textAlign: "center",
                fontSize: 20,
                fontWeight: 600,
                color: on ? COLORS.text : COLORS.textMuted,
              }}
            >
              {label}
              <div
                style={{
                  marginTop: 18,
                  fontSize: 13,
                  fontWeight: 400,
                  color: COLORS.textMuted,
                  lineHeight: 1.5,
                }}
              >
                {i === 0 && "脚注 · 代码 · 引用"}
                {i === 1 && "标题 · 图块 · 扫一眼"}
                {i === 2 && "一页一命题 · 留白"}
              </div>
            </div>
          );
        })}
      </div>

      <div
        style={{
          position: "absolute",
          bottom: 36,
          left: 48,
          fontSize: 13,
          color: COLORS.magenta,
        }}
      >
        动效示意 · 非正文插图
      </div>
    </AbsoluteFill>
  );
};
