/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/* eslint-disable theme-colors/no-literal-colors */
// WebGL renderer: bar colors are raw three.js hex/rgba, not antd theme tokens.
// The scene chrome (background, panels, grid, label text) does read antd tokens
// so the chart follows the light / dark theme like every other viz.
import { useEffect, useRef } from 'react';
import { useTheme } from '@apache-superset/core/theme';
// eslint-disable-next-line no-restricted-syntax
import * as THREE from 'three';
import { Waterfall3DTransformedProps, BarType } from '../types';

const BAR_W = 0.62;
const BAR_D = 0.8;
const SPACING = 1.05;
const LANE_GAP = 2.6; // depth distance between lanes
const AXIS_H = 10; // value range maps to this many world units

// "Nice" axis ticks spanning [min, max].
function niceTicks(min: number, max: number, count = 7): number[] {
  const span = max - min || 1;
  const raw = span / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const norm = raw / mag;
  const step = (norm >= 5 ? 10 : norm >= 2 ? 5 : norm >= 1 ? 2 : 1) * mag;
  const start = Math.ceil(min / step) * step;
  const ticks: number[] = [];
  for (let v = start; v <= max + step * 0.5; v += step) ticks.push(v);
  return ticks;
}

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function makeLabelSprite(
  text: string,
  opts: {
    size?: number;
    color?: string;
    bold?: boolean;
    worldScale?: number;
    bg?: string; // pill fill — turns the label into a chip
    border?: string; // pill stroke
  } = {},
): THREE.Sprite {
  const {
    size = 13,
    color = 'rgba(30,50,100,0.9)',
    bold = false,
    worldScale = 1,
    bg,
    border,
  } = opts;
  const DPR = 2;
  const PADX = bg ? 16 : 12;
  const PADY = bg ? 11 : 7;
  const cv = document.createElement('canvas');
  const ctx = cv.getContext('2d')!;
  const font = `${bold ? '600 ' : ''}${size * DPR}px 'Segoe UI', Arial`;
  ctx.font = font;
  const tw = ctx.measureText(text).width;
  cv.width = Math.ceil(tw) + PADX * 2;
  cv.height = size * DPR + PADY * 2;
  if (bg) {
    const r = cv.height * 0.42;
    roundRect(ctx, 1, 1, cv.width - 2, cv.height - 2, r);
    ctx.fillStyle = bg;
    ctx.fill();
    if (border) {
      ctx.lineWidth = 2.5;
      ctx.strokeStyle = border;
      ctx.stroke();
    }
  }
  ctx.font = font;
  ctx.fillStyle = color;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, cv.width / 2, cv.height / 2);
  const tex = new THREE.CanvasTexture(cv);
  tex.minFilter = THREE.LinearFilter;
  const sp = new THREE.Sprite(
    new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }),
  );
  sp.scale.set(
    (cv.width / 115) * worldScale,
    (cv.height / 115) * worldScale,
    1,
  );
  sp.renderOrder = 999;
  return sp;
}

export default function ThreeWaterfall(props: Waterfall3DTransformedProps) {
  const {
    width,
    height,
    lanes,
    stepOrder,
    colors,
    showValue,
    boldMode,
    showConnectors,
    barWidth,
    autoRotate,
    fmt,
    axisLabels,
    labelColor,
    minVal,
    maxVal,
    tipColumnLabel,
    tipByCell,
  } = props;

  const theme = useTheme();
  // Falls back to the theme's text color when the user left the control unset,
  // so labels stay readable on both a light and a dark background.
  const textColor = labelColor || theme.colorText;
  // Chip fill behind the step / lane labels.
  const pillBg = theme.colorBgElevated;

  // Re-alpha a `rgba(r,g,b,a)` string (used to derive softer / border variants).
  const withAlpha = (rgba: string, a: number) =>
    rgba.replace(/rgba?\(([^)]+)\)/, (_, body) => {
      const [r, g, b] = body.split(',');
      return `rgba(${r.trim()},${g.trim()},${b.trim()},${a})`;
    });

  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return undefined;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch (e) {
      // No WebGL (e.g. headless thumbnail) — show a graceful message.
      mount.innerHTML =
        '<div style="display:flex;height:100%;align-items:center;justify-content:center;color:#888;font:13px sans-serif">3D rendering requires WebGL</div>';
      return undefined;
    }

    const W = Math.max(width, 10);
    const H = Math.max(height, 10);
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;
    renderer.domElement.style.display = 'block';
    mount.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    // Left transparent on purpose: painting a background means guessing the
    // colour of whatever the chart is dropped into, and any mismatch reads as a
    // solid block sitting on the dashboard. Inheriting the container is right in
    // every theme, and matches how the echarts-gl charts already behave.
    scene.background = null;

    // ── Scale value → world Y ───────────────────────────────────────────────
    const range = maxVal - minVal || 1;
    const SCALE = AXIS_H / range;
    const yOf = (v: number) => (v - minVal) * SCALE;

    const nSteps = stepOrder.length;
    const nLanes = Math.max(lanes.length, 1);
    const stepIndex = new Map(stepOrder.map((s, i) => [s, i]));
    const xSpan = (nSteps - 1) * SPACING;
    const zSpan = (nLanes - 1) * LANE_GAP;
    const CX = xSpan / 2;
    const CZ = zSpan / 2;
    const bw = Math.max(0.2, Math.min(0.95, barWidth / 18)) || BAR_W;
    // Labels keep a fixed world scale, so they shrink to specks in a wide scene.
    // Grow them proportionally to the footprint (clamped) to stay legible.
    const LBL = Math.min(3.2, Math.max(1, Math.max(xSpan, zSpan) / 20));

    // ── Camera ──────────────────────────────────────────────────────────────
    const camera = new THREE.PerspectiveCamera(40, W / H, 0.1, 600);
    const lookAt = new THREE.Vector3(CX, AXIS_H * 0.32, CZ);
    const sph = {
      theta: 0.7,
      phi: 1.0,
      r: Math.max(xSpan, zSpan, 14) * 0.82 + 9,
    };
    const posCamera = () => {
      camera.position.set(
        lookAt.x + sph.r * Math.sin(sph.phi) * Math.sin(sph.theta),
        lookAt.y + sph.r * Math.cos(sph.phi),
        lookAt.z + sph.r * Math.sin(sph.phi) * Math.cos(sph.theta),
      );
      camera.lookAt(lookAt);
    };
    posCamera();

    // ── Lights ──────────────────────────────────────────────────────────────
    scene.add(new THREE.AmbientLight(0xaabbdd, 3.2));
    const sun = new THREE.DirectionalLight(0xffffff, 1.9);
    sun.position.set(xSpan * 0.4 + 10, AXIS_H * 2.6, zSpan + 18);
    sun.castShadow = true;
    sun.shadow.mapSize.set(2048, 2048);
    sun.shadow.camera.left = -4;
    sun.shadow.camera.right = xSpan + 6;
    sun.shadow.camera.top = AXIS_H + 8;
    sun.shadow.camera.bottom = -4;
    sun.shadow.camera.far = 200;
    scene.add(sun);
    const fill = new THREE.DirectionalLight(0x88aaee, 0.4);
    fill.position.set(-12, AXIS_H, -zSpan - 12);
    scene.add(fill);

    // ── Box: floor + back wall + side wall (echarts-gl grid3D family look) ────
    // Three open panels with light split-line grids, like the other 3D charts.
    const PAD = 2.4;
    const gx0 = -PAD; // left edge (first step at x=0)
    const gx1 = xSpan + PAD; // right edge
    const gz0 = -PAD; // back edge (front lane at z=0)
    const gz1 = zSpan + PAD; // front edge
    const yTop = AXIS_H * 1.04; // wall height (value range maps to AXIS_H)
    const ticks = niceTicks(minVal, maxVal);

    const PANEL = theme.colorBgLayout;
    const GRID = theme.colorBorder;
    const panelMat = (side: number) =>
      new THREE.MeshBasicMaterial({
        color: PANEL,
        transparent: true,
        opacity: 0.55,
        side,
        depthWrite: false,
      });
    const gridMat = new THREE.LineBasicMaterial({
      color: GRID,
      transparent: true,
      opacity: 0.9,
    });
    const seg = (a: THREE.Vector3, b: THREE.Vector3, out: THREE.Vector3[]) => {
      out.push(a, b);
    };

    // Floor panel (X-Z at y=0).
    const floor = new THREE.Mesh(
      new THREE.PlaneGeometry(gx1 - gx0, gz1 - gz0),
      new THREE.MeshLambertMaterial({ color: PANEL }),
    );
    floor.rotation.x = -Math.PI / 2;
    floor.position.set((gx0 + gx1) / 2, -0.01, (gz0 + gz1) / 2);
    floor.receiveShadow = true;
    scene.add(floor);

    // Back wall (X-Y at z=gz0) and side wall (Y-Z at x=gx0).
    const backWall = new THREE.Mesh(
      new THREE.PlaneGeometry(gx1 - gx0, yTop),
      panelMat(THREE.DoubleSide),
    );
    backWall.position.set((gx0 + gx1) / 2, yTop / 2, gz0);
    scene.add(backWall);
    const sideWall = new THREE.Mesh(
      new THREE.PlaneGeometry(gz1 - gz0, yTop),
      panelMat(THREE.DoubleSide),
    );
    sideWall.rotation.y = Math.PI / 2;
    sideWall.position.set(gx0, yTop / 2, (gz0 + gz1) / 2);
    scene.add(sideWall);

    // Grid lines on the three panels.
    const lp: THREE.Vector3[] = [];
    const GSTEP = 1.1;
    // Floor: lines along X and Z.
    for (let gx = gx0; gx <= gx1 + 1e-3; gx += GSTEP)
      seg(new THREE.Vector3(gx, 0, gz0), new THREE.Vector3(gx, 0, gz1), lp);
    for (let gz = gz0; gz <= gz1 + 1e-3; gz += GSTEP)
      seg(new THREE.Vector3(gx0, 0, gz), new THREE.Vector3(gx1, 0, gz), lp);
    // Walls: horizontal value lines at each tick.
    ticks.forEach(v => {
      const y = yOf(v);
      if (y < -1e-3 || y > yTop + 1e-3) return;
      seg(new THREE.Vector3(gx0, y, gz0), new THREE.Vector3(gx1, y, gz0), lp); // back
      seg(new THREE.Vector3(gx0, y, gz0), new THREE.Vector3(gx0, y, gz1), lp); // side
    });
    // Back wall: faint verticals at the box edges; side wall: lane verticals.
    seg(new THREE.Vector3(gx0, 0, gz0), new THREE.Vector3(gx0, yTop, gz0), lp);
    seg(new THREE.Vector3(gx1, 0, gz0), new THREE.Vector3(gx1, yTop, gz0), lp);
    seg(new THREE.Vector3(gx0, 0, gz1), new THREE.Vector3(gx0, yTop, gz1), lp);
    scene.add(
      new THREE.LineSegments(
        new THREE.BufferGeometry().setFromPoints(lp),
        gridMat,
      ),
    );

    // ── Value tick labels on the left/back corner ───────────────────────────
    ticks.forEach(v => {
      const y = yOf(v);
      if (y < -1e-3 || y > yTop + 1e-3) return;
      const lbl = makeLabelSprite(fmt(v), {
        size: 11,
        color: withAlpha(textColor, 0.85),
        worldScale: LBL,
      });
      lbl.position.set(gx0 - 0.6 * LBL, y, gz0);
      scene.add(lbl);
    });
    // Y axis title
    const yTitle = makeLabelSprite(axisLabels.y, {
      size: 13,
      color: textColor,
      bold: true,
      worldScale: LBL,
    });
    yTitle.position.set(gx0 - 1.4 * LBL, yTop + 0.4, gz0);
    scene.add(yTitle);

    // ── Bars ────────────────────────────────────────────────────────────────
    const colorOf: Record<BarType, number> = {
      positive: colors.positive,
      negative: colors.negative,
      total: colors.total,
      subtotal: colors.subtotal,
    };
    const emissiveOf = (hex: number) => {
      const c = new THREE.Color(hex);
      c.multiplyScalar(0.22);
      return c.getHex();
    };
    const barMeshes: THREE.Mesh[] = [];
    const disposables: { dispose: () => void }[] = [];

    lanes.forEach((lane, li) => {
      const z = li * LANE_GAP;
      let prevX: number | null = null;
      let prevY: number | null = null;
      lane.bars.forEach(bar => {
        const xi = stepIndex.get(bar.step);
        if (xi == null) return;
        const x = xi * SPACING;
        const lo = yOf(Math.min(bar.base, bar.top));
        const hi = yOf(Math.max(bar.base, bar.top));
        const h = Math.max(hi - lo, 0.02);
        const hex = colorOf[bar.type];

        const geo = new THREE.BoxGeometry(bw, h, BAR_D);
        const mat = new THREE.MeshPhongMaterial({
          color: hex,
          emissive: emissiveOf(hex),
          shininess: 90,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, (lo + hi) / 2, z);
        mesh.castShadow = true;
        mesh.receiveShadow = true;
        (mesh.userData as any) = {
          lane: lane.cat,
          bar,
          baseEmissive: emissiveOf(hex),
        };
        scene.add(mesh);
        barMeshes.push(mesh);
        disposables.push(geo, mat);

        const edges = new THREE.LineSegments(
          new THREE.EdgesGeometry(geo),
          new THREE.LineBasicMaterial({
            color: 0x000000,
            transparent: true,
            opacity: 0.08,
          }),
        );
        edges.position.copy(mesh.position);
        scene.add(edges);

        // Value label above/below the bar.
        if (showValue && h > 0.05) {
          const isKey = bar.type === 'total' || bar.type === 'subtotal';
          const bold =
            (boldMode === 'both' && isKey) ||
            (boldMode === 'total' && bar.type === 'total') ||
            (boldMode === 'subtotal' && bar.type === 'subtotal');
          const col =
            bar.type === 'positive'
              ? 'rgba(21,128,61,1)'
              : bar.type === 'negative'
                ? 'rgba(185,28,28,1)'
                : bar.type === 'subtotal'
                  ? 'rgba(91,33,182,1)'
                  : 'rgba(30,64,175,1)';
          const sp = makeLabelSprite(fmt(bar.value), {
            size: 12,
            color: col,
            bold,
            worldScale: LBL,
            bg: pillBg,
            border: col.replace(/,1\)$/, ',0.45)'),
          });
          const yLab = bar.value >= 0 ? hi + 0.34 * LBL : lo - 0.34 * LBL;
          sp.position.set(x, yLab, z + 0.5);
          scene.add(sp);
        }

        // Connector from previous bar top to this bar (within a lane).
        if (
          showConnectors &&
          prevX !== null &&
          prevY !== null &&
          bar.type !== 'total' &&
          bar.type !== 'subtotal'
        ) {
          const pts = [
            new THREE.Vector3(prevX + bw / 2, prevY, z),
            new THREE.Vector3(x - bw / 2, prevY, z),
          ];
          scene.add(
            new THREE.Line(
              new THREE.BufferGeometry().setFromPoints(pts),
              new THREE.LineBasicMaterial({
                color: 0x6688cc,
                transparent: true,
                opacity: 0.5,
              }),
            ),
          );
        }
        prevX = x;
        prevY = yOf(bar.running);
      });

      // Lane (depth category) label at the front of each lane.
      const laneLbl = makeLabelSprite(lane.cat, {
        size: 12,
        color: textColor,
        bold: true,
        worldScale: LBL,
        bg: pillBg,
        border: withAlpha(textColor, 0.4),
      });
      laneLbl.position.set(xSpan + 1.6 * LBL, 0.2, z);
      scene.add(laneLbl);
    });

    // ── Step labels at base (front lane); key steps always, others sparse ───
    stepOrder.forEach((step, i) => {
      const isKey = lanes.some(l =>
        l.bars.some(
          b => b.step === step && (b.type === 'total' || b.type === 'subtotal'),
        ),
      );
      if (!isKey && i % 3 !== 0) return;
      const sp = makeLabelSprite(step, {
        size: isKey ? 12 : 10,
        color: isKey ? textColor : withAlpha(textColor, 0.75),
        bold: isKey,
        worldScale: LBL,
        ...(isKey ? { bg: pillBg, border: withAlpha(textColor, 0.4) } : {}),
      });
      sp.position.set(i * SPACING, -0.55 * LBL, -0.4);
      scene.add(sp);
    });

    // ── Tooltip ─────────────────────────────────────────────────────────────
    const tip = document.createElement('div');
    Object.assign(tip.style, {
      position: 'absolute',
      pointerEvents: 'none',
      display: 'none',
      background: 'rgba(255,255,255,0.97)',
      border: '1px solid rgba(60,100,200,0.18)',
      borderRadius: '10px',
      padding: '10px 14px',
      color: '#1a2a4a',
      font: "12px 'Segoe UI', system-ui, Arial",
      boxShadow: '0 8px 28px rgba(60,100,200,0.16)',
      zIndex: '10',
      minWidth: '160px',
    } as CSSStyleDeclaration);
    mount.appendChild(tip);

    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();
    let hovered: THREE.Mesh | null = null;

    // ── Interaction (orbit / pan / zoom) ────────────────────────────────────
    let drag = false;
    let rdrag = false;
    let px = 0;
    let py = 0;
    const el = renderer.domElement;

    const onDown = (e: MouseEvent) => {
      if (e.button === 0) drag = true;
      if (e.button === 2) rdrag = true;
      px = e.clientX;
      py = e.clientY;
    };
    const onUp = () => {
      drag = false;
      rdrag = false;
    };
    const onCtx = (e: Event) => e.preventDefault();
    const onMove = (e: MouseEvent) => {
      if (drag) {
        sph.theta -= (e.clientX - px) * 0.006;
        sph.phi = Math.max(
          0.08,
          Math.min(Math.PI / 2 - 0.04, sph.phi + (e.clientY - py) * 0.006),
        );
        px = e.clientX;
        py = e.clientY;
        posCamera();
        return;
      }
      if (rdrag) {
        lookAt.x -= (e.clientX - px) * 0.03;
        lookAt.y += (e.clientY - py) * 0.03;
        px = e.clientX;
        py = e.clientY;
        posCamera();
        return;
      }
      const rect = el.getBoundingClientRect();
      mouse.set(
        ((e.clientX - rect.left) / rect.width) * 2 - 1,
        -((e.clientY - rect.top) / rect.height) * 2 + 1,
      );
      raycaster.setFromCamera(mouse, camera);
      const hits = raycaster.intersectObjects(barMeshes);
      if (hovered && (!hits.length || hits[0].object !== hovered)) {
        (hovered.material as THREE.MeshPhongMaterial).emissive.setHex(
          (hovered.userData as any).baseEmissive,
        );
        hovered = null;
      }
      if (hits.length) {
        const m = hits[0].object as THREE.Mesh;
        if (m !== hovered) {
          (m.material as THREE.MeshPhongMaterial).emissive.setHex(0x555555);
          hovered = m;
        }
        const { lane, bar } = m.userData as any;
        const tipRow =
          tipColumnLabel && tipByCell[`${lane} ${bar.step}`]
            ? `<div style="color:rgba(80,100,140,0.7)">${tipColumnLabel}: ${tipByCell[`${lane} ${bar.step}`]}</div>`
            : '';
        const kind =
          bar.type === 'total'
            ? 'Total'
            : bar.type === 'subtotal'
              ? 'Subtotal'
              : bar.type === 'positive'
                ? 'Increase'
                : 'Decrease';
        tip.innerHTML =
          `<div style="font-weight:700;color:#2255bb;margin-bottom:6px">${lane} · ${bar.step}</div>` +
          tipRow +
          `<div style="display:flex;justify-content:space-between;gap:18px"><span style="color:rgba(80,100,140,0.7)">${kind}</span><b>${fmt(bar.value)}</b></div>` +
          `<div style="display:flex;justify-content:space-between;gap:18px"><span style="color:rgba(80,100,140,0.7)">Running total</span><b>${fmt(bar.running)}</b></div>`;
        tip.style.display = 'block';
        tip.style.left = `${e.clientX - rect.left + 16}px`;
        tip.style.top = `${e.clientY - rect.top - 8}px`;
      } else {
        tip.style.display = 'none';
      }
    };
    const onWheel = (e: WheelEvent) => {
      sph.r = Math.max(8, Math.min(xSpan * 3 + 80, sph.r + e.deltaY * 0.05));
      posCamera();
    };

    el.addEventListener('mousedown', onDown);
    window.addEventListener('mouseup', onUp);
    window.addEventListener('mousemove', onMove);
    el.addEventListener('contextmenu', onCtx);
    el.addEventListener('wheel', onWheel, { passive: true });

    // ── Render loop ─────────────────────────────────────────────────────────
    let raf = 0;
    const tick = () => {
      raf = requestAnimationFrame(tick);
      if (autoRotate && !drag) {
        sph.theta += 0.0022;
        posCamera();
      }
      renderer.render(scene, camera);
    };
    tick();

    // ── Cleanup ─────────────────────────────────────────────────────────────
    return () => {
      cancelAnimationFrame(raf);
      el.removeEventListener('mousedown', onDown);
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('mousemove', onMove);
      el.removeEventListener('contextmenu', onCtx);
      el.removeEventListener('wheel', onWheel);
      disposables.forEach(d => d.dispose());
      scene.traverse(obj => {
        const any = obj as any;
        if (any.geometry?.dispose) any.geometry.dispose();
        const mat = any.material;
        if (mat) {
          (Array.isArray(mat) ? mat : [mat]).forEach((m: any) => {
            m.map?.dispose?.();
            m.dispose?.();
          });
        }
      });
      renderer.dispose();
      if (tip.parentNode) tip.parentNode.removeChild(tip);
      if (renderer.domElement.parentNode) {
        renderer.domElement.parentNode.removeChild(renderer.domElement);
      }
    };
  }, [
    width,
    height,
    lanes,
    stepOrder,
    colors,
    showValue,
    boldMode,
    showConnectors,
    barWidth,
    autoRotate,
    fmt,
    axisLabels,
    textColor,
    pillBg,
    theme,
    minVal,
    maxVal,
    tipColumnLabel,
    tipByCell,
  ]);

  return (
    <div
      ref={mountRef}
      style={{ width, height, position: 'relative', overflow: 'hidden' }}
    />
  );
}
