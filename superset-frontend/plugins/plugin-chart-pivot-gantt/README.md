<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# @superset-ui/plugin-chart-pivot-gantt

Hierarchical pivot table (rows + metrics + subtotals per level) with a Gantt
calendar on the right: one marker per row between a start and an end date,
progress fill, labels around/inside the marker, legend by first level, zoom
slider and current-day line.

Viz key: `pivot_gantt` (same key and `form_data` names as the "Pivot Gantt"
chart of the Superset TA fork, so charts exported from it load unchanged).

## Queries

`buildQuery` emits `2 + N` queries (N = number of hierarchy columns):

| # | columns | metrics | purpose |
|---|---------|---------|---------|
| 0 | hierarchy + start/end + label columns | none | raw rows → markers |
| 1 | none | all | grand total |
| 2..N+1 | hierarchy prefix `rows[0..i]` | all | subtotal per level |

`time_grain_sqla` is removed so the calendar always receives raw dates.

## Controls (form_data)

`groupbyRows`, `metrics`, `date_start_col`, `date_end_col`, `adhoc_filters`,
`emit_full_hierarchy`, `row_limit`, `order_by_col`, `order_desc`,
`default_collapsed_level`, `marker_progress_col`, `marker_description_cols`,
`marker_label_{left,right,top,bottom}_col`, `showGrandTotal`,
`hideExpandedRows`, `valueFormat`, `date_format`, `value_font_size`,
`header_font_size`, `label_align`, `metrics_config`, `color_scheme`,
`show_marker_label`, `marker_font_size`, `marker_font_color`, `marker_height`,
`marker_label_align`, `marker_description_{font_size,font_color,label_align}`,
`marker_detail_{font_size,font_color}`, `show_hint`, `hint_wrap_text`,
`hint_font_size`, `hint_trigger`, `show_day_line`, `show_legend`,
`legend_name`, `legend_font_size`, `timeline_format` (`P1Y|P3M|P1M|P1W|P1D`,
multi), `timeline_font_size`, `slider_values` (hidden, persisted by the chart).

## Not ported (v1)

Advanced conditional formatting with row colouring, `hierarchy_config` /
`column_config` column customisation, drill-by / context menu, ISO week
numbering in the header.
