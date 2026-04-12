import React from "react";
import { Composition } from "remotion";
import { DataFlow } from "./DataFlow";
import { DualCarrierThreeTimes } from "./DualCarrierThreeTimes";
import { PathStrategy } from "./PathStrategy";
import { ReadingModes } from "./ReadingModes";
import { SameOriginLayers } from "./SameOriginLayers";
import { ThreePathsFriction } from "./ThreePathsFriction";
import { FPS, H, W } from "./theme";

export const Root: React.FC = () => {
  return (
    <>
      <Composition
        id="dual-carrier"
        component={DualCarrierThreeTimes}
        durationInFrames={150}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{}}
      />
      <Composition
        id="three-paths-friction"
        component={ThreePathsFriction}
        durationInFrames={180}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{}}
      />
      <Composition
        id="same-origin-layers"
        component={SameOriginLayers}
        durationInFrames={150}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{}}
      />
      <Composition
        id="path-strategy"
        component={PathStrategy}
        durationInFrames={120}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{}}
      />
      <Composition
        id="reading-modes"
        component={ReadingModes}
        durationInFrames={180}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{}}
      />
      <Composition
        id="data-flow"
        component={DataFlow}
        durationInFrames={180}
        fps={FPS}
        width={W}
        height={H}
        defaultProps={{}}
      />
    </>
  );
};
