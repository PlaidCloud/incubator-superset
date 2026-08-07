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

// Pure-TS regression (no echarts-stat / no new npm dep). Least squares for
// linear/exponential/logarithmic/power, and Gaussian elimination for polynomial.

export type RegressionType =
  | 'linear'
  | 'exponential'
  | 'logarithmic'
  | 'power'
  | 'polynomial';

export interface RegressionResult {
  predict: (x: number) => number;
  r2: number;
  equation: string;
}

type Point = [number, number];

function fmt(n: number): string {
  if (!Number.isFinite(n)) return '0';
  const a = Math.abs(n);
  if (a !== 0 && (a < 1e-3 || a >= 1e6)) return n.toExponential(2);
  return Number(n.toFixed(4)).toString();
}

function rSquared(points: Point[], predict: (x: number) => number): number {
  const ys = points.map(p => p[1]);
  const mean = ys.reduce((a, b) => a + b, 0) / (ys.length || 1);
  let ssTot = 0;
  let ssRes = 0;
  for (const [x, y] of points) {
    const yhat = predict(x);
    if (!Number.isFinite(yhat)) continue;
    ssTot += (y - mean) ** 2;
    ssRes += (y - yhat) ** 2;
  }
  if (ssTot === 0) return 0;
  return Math.max(0, Math.min(1, 1 - ssRes / ssTot));
}

// Ordinary least squares for y = a + b*x, returns [a, b].
function ols(points: Point[]): [number, number] {
  const n = points.length;
  let sx = 0;
  let sy = 0;
  let sxx = 0;
  let sxy = 0;
  for (const [x, y] of points) {
    sx += x;
    sy += y;
    sxx += x * x;
    sxy += x * y;
  }
  const denom = n * sxx - sx * sx || 1e-9;
  const b = (n * sxy - sx * sy) / denom;
  const a = (sy - b * sx) / n;
  return [a, b];
}

// Solve a linear system A·x = y via Gaussian elimination with partial pivoting.
function solve(A: number[][], y: number[]): number[] {
  const n = y.length;
  const m = A.map((row, i) => [...row, y[i]]);
  for (let col = 0; col < n; col += 1) {
    let pivot = col;
    for (let r = col + 1; r < n; r += 1) {
      if (Math.abs(m[r][col]) > Math.abs(m[pivot][col])) pivot = r;
    }
    [m[col], m[pivot]] = [m[pivot], m[col]];
    const pv = m[col][col] || 1e-9;
    for (let r = 0; r < n; r += 1) {
      if (r === col) continue;
      const factor = m[r][col] / pv;
      for (let c = col; c <= n; c += 1) m[r][c] -= factor * m[col][c];
    }
  }
  return m.map((row, i) => row[n] / (row[i] || 1e-9));
}

function polynomial(points: Point[], order: number): RegressionResult {
  const deg = Math.max(1, Math.min(6, order));
  // Build normal equations for least-squares polynomial fit.
  const A: number[][] = [];
  const y: number[] = [];
  for (let i = 0; i <= deg; i += 1) {
    const row: number[] = [];
    for (let j = 0; j <= deg; j += 1) {
      row.push(points.reduce((s, [px]) => s + px ** (i + j), 0));
    }
    A.push(row);
    y.push(points.reduce((s, [px, py]) => s + py * px ** i, 0));
  }
  const coeffs = solve(A, y);
  const predict = (x: number) =>
    coeffs.reduce((s, c, i) => s + c * x ** i, 0);
  const terms = coeffs
    .map((c, i) => (i === 0 ? fmt(c) : `${fmt(c)}·x${i > 1 ? `^${i}` : ''}`))
    .reverse()
    .join(' + ');
  return { predict, r2: rSquared(points, predict), equation: `y = ${terms}` };
}

export function fitRegression(
  points: Point[],
  type: RegressionType,
  order = 2,
): RegressionResult | null {
  const clean = points.filter(
    ([x, y]) => Number.isFinite(x) && Number.isFinite(y),
  );
  if (clean.length < 2) return null;

  switch (type) {
    case 'exponential': {
      // y = a·e^(b·x)  ->  ln y = ln a + b·x  (needs y > 0)
      const pts = clean.filter(([, y]) => y > 0).map(([x, y]) => [x, Math.log(y)] as Point);
      if (pts.length < 2) return null;
      const [lnA, b] = ols(pts);
      const a = Math.exp(lnA);
      const predict = (x: number) => a * Math.exp(b * x);
      return { predict, r2: rSquared(clean, predict), equation: `y = ${fmt(a)}·e^(${fmt(b)}·x)` };
    }
    case 'logarithmic': {
      // y = a + b·ln x  (needs x > 0)
      const pts = clean.filter(([x]) => x > 0).map(([x, y]) => [Math.log(x), y] as Point);
      if (pts.length < 2) return null;
      const [a, b] = ols(pts);
      const predict = (x: number) => (x > 0 ? a + b * Math.log(x) : NaN);
      return { predict, r2: rSquared(clean, predict), equation: `y = ${fmt(a)} + ${fmt(b)}·ln(x)` };
    }
    case 'power': {
      // y = a·x^b  ->  ln y = ln a + b·ln x  (needs x,y > 0)
      const pts = clean
        .filter(([x, y]) => x > 0 && y > 0)
        .map(([x, y]) => [Math.log(x), Math.log(y)] as Point);
      if (pts.length < 2) return null;
      const [lnA, b] = ols(pts);
      const a = Math.exp(lnA);
      const predict = (x: number) => (x > 0 ? a * x ** b : NaN);
      return { predict, r2: rSquared(clean, predict), equation: `y = ${fmt(a)}·x^${fmt(b)}` };
    }
    case 'polynomial':
      return polynomial(clean, order);
    case 'linear':
    default: {
      const [a, b] = ols(clean);
      const predict = (x: number) => a + b * x;
      return { predict, r2: rSquared(clean, predict), equation: `y = ${fmt(a)} + ${fmt(b)}·x` };
    }
  }
}

// Sample the fitted curve across the x-range into [x, y] pairs for a line series.
export function sampleCurve(
  fit: RegressionResult,
  xMin: number,
  xMax: number,
  steps = 80,
): Point[] {
  const out: Point[] = [];
  if (!Number.isFinite(xMin) || !Number.isFinite(xMax) || xMax <= xMin) return out;
  const dx = (xMax - xMin) / steps;
  for (let i = 0; i <= steps; i += 1) {
    const x = xMin + i * dx;
    const y = fit.predict(x);
    if (Number.isFinite(y)) out.push([x, y]);
  }
  return out;
}
