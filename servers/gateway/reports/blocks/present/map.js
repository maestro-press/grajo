/**
 * The `map` present block: the run's items as a static inline SVG point plot.
 *
 * Settings: `{latField: string, lonField: string, labelField?: string}`. The plot is drawn HERE, as one
 * SVG file the document carries as an asset, because the artifacts render kit has no map layer and a
 * recipient view is script free: numbered markers on a plain field, no basemap, no tiles, no script and
 * no link of any kind. The markers' numbers are listed under the image, one line per point, so the plot
 * says which item each dot is without putting item text inside the drawing. A label is the run's own data
 * and is written as escaped markdown whose bare hosts and addresses are broken, so a label reading
 * `www.evil.example` stays text instead of becoming a link the recipe never named.
 *
 * Every coordinate must be a finite latitude in [-90, 90] and longitude in [-180, 180]; anything else is
 * left out of the plot rather than placed somewhere wrong. At most 200 points are drawn, and a run with
 * no placeable point adds no section at all.
 */
import { escapeMd, readItemField } from "../../document.js";
import { breakUrlText } from "../../email/neutralize-links.js";

const WIDTH = 640;
const HEIGHT = 400;
const PAD = 24;
const MAX_POINTS = 200;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  for (const field of ["latField", "lonField"]) {
    if (typeof settings[field] !== "string" || !settings[field].trim()) errors.push(field);
  }
  if (Object.hasOwn(settings, "labelField") && typeof settings.labelField !== "string") {
    errors.push("labelField");
  }
  return errors;
}

/** A coordinate as a finite number, or null. */
function numberOf(value) {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/** XML text escaping for anything drawn into the SVG. */
function escXml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** One coordinate as SVG text: two decimals, and a number either way. */
function coordText(value) {
  return (Math.round(value * 100) / 100).toFixed(2);
}

/** Where a coordinate sits in the plot box: the ranges are fitted, a flat range is centred. */
function project(points) {
  const lats = points.map((point) => point.lat);
  const lons = points.map((point) => point.lon);
  const minLat = Math.min(...lats);
  const maxLat = Math.max(...lats);
  const minLon = Math.min(...lons);
  const maxLon = Math.max(...lons);
  const innerW = WIDTH - PAD * 2;
  const innerH = HEIGHT - PAD * 2;
  return points.map((point) => {
    const x = maxLon === minLon
      ? PAD + innerW / 2
      : PAD + ((point.lon - minLon) / (maxLon - minLon)) * innerW;
    const y = maxLat === minLat
      ? PAD + innerH / 2
      : HEIGHT - PAD - ((point.lat - minLat) / (maxLat - minLat)) * innerH;
    return { ...point, x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 };
  });
}

/** The whole plot as one `<svg>` element: a background, then numbered markers. */
function plotSvg(points) {
  const marks = points.map((point, index) => [
    `<circle cx="${point.x}" cy="${point.y}" r="9" fill="#e2a03f" stroke="#1d1d1f" stroke-width="1"/>`,
    `<text x="${point.x}" y="${point.y}" text-anchor="middle" dominant-baseline="central"`,
    ` font-family="sans-serif" font-size="11" fill="#1d1d1f">${index + 1}</text>`,
  ].join(""));
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${WIDTH} ${HEIGHT}"`,
    ` width="${WIDTH}" height="${HEIGHT}" role="img">`,
    `<rect x="0" y="0" width="${WIDTH}" height="${HEIGHT}" fill="#ffffff" stroke="#d0d0d0"/>`,
    ...marks,
    "</svg>",
  ].join("");
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const latField = typeof settings.latField === "string" ? settings.latField : "";
  const lonField = typeof settings.lonField === "string" ? settings.lonField : "";
  const labelField = typeof settings.labelField === "string" ? settings.labelField : "";
  const items = Array.isArray(input?.items) ? input.items : [];
  const sections = Array.isArray(input?.sections) ? input.sections : [];

  const points = [];
  for (const item of items) {
    const lat = numberOf(readItemField(item, latField));
    const lon = numberOf(readItemField(item, lonField));
    if (lat == null || lon == null) continue;
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) continue;
    const label = labelField ? readItemField(item, labelField) : null;
    points.push({ lat, lon, label: label == null ? "" : String(label) });
    if (points.length >= MAX_POINTS) break;
  }
  if (!points.length) return { items, sections };

  const projected = project(points);
  const svg = plotSvg(projected);
  const assetPath = `map-${ctx.blockId}.svg`;
  const asset = {
    path: assetPath,
    contentType: "image/svg+xml",
    base64: Buffer.from(svg, "utf8").toString("base64"),
  };
  const legend = projected.map((point, index) => {
    const coords = `${coordText(point.lat)}, ${coordText(point.lon)}`;
    return `${index + 1}. ${point.label ? `${breakUrlText(escapeMd(point.label))} (${coords})` : coords}`;
  });
  const markdown = [`![${points.length}](${assetPath})`, "", ...legend].join("\n");
  const section = { type: "map", blockId: ctx.blockId, markdown, assets: [asset] };
  return { items, sections: [...sections, section] };
}

export const mapBlock = Object.freeze({
  type: "map",
  kind: "present",
  sourceBearing: false,
  validate,
  run,
});