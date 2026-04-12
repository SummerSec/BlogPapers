import React from "react";
import { AbsoluteFill, useCurrentFrame } from "remotion";
import { COLORS } from "./theme";

const modes = ["分栏对照", "仅正文", "仅看 PPT", "独立打开"] as const;
const seg = 36;

export const ReadingModes: React.FC = () => {
  const frame = useCurrentFrame();
  const active = Math.floor((frame % (seg * modes.length)) / seg);

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
          color: COLORS.green,
        }}
      >
        文章页阅读模式（示意）
      </div>

      <div
        style={{
          position: "absolute",
          top: 200,
          left: 80,
          right: 80,
          display: "flex",
          gap: 16,
          justifyContent: "center",
        }}
      >
        {modes.map((m, i) => {
          const on = active === i;
          return (
            <div
              key={m}
              style={{
                padding: "14px 22px",
                borderRadius: 999,
                fontSize: 16,
                fontWeight: 600,
                border: `2px solid ${on ? COLORS.accent : COLORS.border}`,
                background: on ? "rgba(92, 219, 207, 0.15)" : "rgba(11, 15, 26, 0.5)",
                color: on ? COLORS.text : COLORS.textMuted,
                boxShadow: on ? "0 0 28px rgba(92, 219, 207, 0.25)" : "none",
              }}
            >
              {m}
            </div>
          );
        })}
      </div>

      <div
        style={{
          position: "absolute",
          top: 360,
          left: 100,
          right: 100,
          height: 220,
          borderRadius: 14,
          border: `1px solid ${COLORS.border}`,
          background: "rgba(8, 11, 20, 0.5)",
          display: "flex",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            flex: active === 2 ? "0 0 8%" : active === 1 ? "1 1 100%" : "1 1 52%",
            background: "rgba(92, 219, 207, 0.04)",
            borderRight: `1px solid ${COLORS.border}`,
            padding: 16,
            fontSize: 12,
            color: COLORS.textMuted,
          }}
        >
          正文列 · utterances
        </div>
        {active !== 1 && (
          <div
            style={{
              flex: active === 2 ? "1 1 92%" : "1 1 48%",
              background: "rgba(148, 168, 232, 0.06)",
              padding: 16,
              fontSize: 12,
              color: COLORS.textMuted,
            }}
          >
            iframe · deck
          </div>
        )}
      </div>
    </AbsoluteFill>
  );
};
