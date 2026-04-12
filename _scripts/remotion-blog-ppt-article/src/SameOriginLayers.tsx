import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { COLORS } from "./theme";

export const SameOriginLayers: React.FC = () => {
  const frame = useCurrentFrame();
  const scan = interpolate(frame % 120, [0, 60, 120], [0, 1, 0]);

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
          color: COLORS.accent,
        }}
      >
        借 token，不搬整站壳
      </div>

      <div
        style={{
          position: "absolute",
          top: 200,
          left: 120,
          width: 420,
          height: 280,
          borderRadius: 16,
          border: `2px solid ${COLORS.accent}`,
          background: "rgba(92, 219, 207, 0.06)",
          padding: 20,
        }}
      >
        <div style={{ fontSize: 15, color: COLORS.accent, marginBottom: 12 }}>
          deck 内继承
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
          {[COLORS.accent, COLORS.magenta, COLORS.green].map((c) => (
            <div
              key={c}
              style={{
                width: 56,
                height: 18,
                borderRadius: 4,
                background: c,
                opacity: 0.85,
              }}
            />
          ))}
        </div>
        <div style={{ fontSize: 13, color: COLORS.textMuted }}>
          色板 · 字体气质 · 与 style.scss 对齐
        </div>
      </div>

      <div
        style={{
          position: "absolute",
          top: 200,
          left: 620,
          width: 480,
          height: 280,
          borderRadius: 16,
          border: `2px dashed ${COLORS.textMuted}`,
          background: "rgba(97, 107, 128, 0.12)",
          padding: 20,
          opacity: interpolate(scan, [0, 1], [0.45, 0.95]),
        }}
      >
        <div style={{ fontSize: 15, color: COLORS.danger, marginBottom: 10 }}>
          不塞进 iframe
        </div>
        <div style={{ fontSize: 13, color: COLORS.textMuted, lineHeight: 1.6 }}>
          全站 header / footer / Liquid / 评论壳 → 默认不搬进单文件 HTML 幻灯
        </div>
      </div>

      <div
        style={{
          position: "absolute",
          top: 520,
          left: 120,
          fontSize: 14,
          color: COLORS.magenta,
        }}
      >
        同源 = 语境一致，不是「再克隆一个博客」
      </div>
    </AbsoluteFill>
  );
};
