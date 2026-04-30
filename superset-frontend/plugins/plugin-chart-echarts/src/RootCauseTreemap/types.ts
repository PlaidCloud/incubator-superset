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
import {
  ChartDataResponseResult,
  ChartProps,
  DataRecordValue,
  QueryFormColumn,
  QueryFormData,
  QueryFormMetric,
} from '@superset-ui/core';
import { CallbackDataParams } from 'echarts/types/src/util/types';
import {
  BaseTransformedProps,
  ContextMenuTransformedProps,
  CrossFilterTransformedProps,
  LabelPositionEnum,
  TreePathInfo,
} from '../types';

export enum RootCauseTreemapLabelType {
  Name = 'name',
  NameValue = 'name_value',
  RootCause = 'root_cause',
}

export enum PerformanceAggregation {
  WeightedAverage = 'weighted_average',
  Average = 'average',
  Sum = 'sum',
}

export enum RootCauseTreemapHierarchyPreset {
  OrderCustomerProductChannel = 'order_customer_product_channel',
  OrderProductChannelCustomer = 'order_product_channel_customer',
  CustomerOrderProductChannel = 'customer_order_product_channel',
  Custom = 'custom',
}

export const ROOT_CAUSE_TREEMAP_HIERARCHIES: Record<
  Exclude<
    RootCauseTreemapHierarchyPreset,
    RootCauseTreemapHierarchyPreset.Custom
  >,
  QueryFormColumn[]
> = {
  [RootCauseTreemapHierarchyPreset.OrderCustomerProductChannel]: [
    'order_type',
    'l3_customer',
    'product',
    'channel',
  ],
  [RootCauseTreemapHierarchyPreset.OrderProductChannelCustomer]: [
    'order_type',
    'product',
    'channel',
    'l3_customer',
  ],
  [RootCauseTreemapHierarchyPreset.CustomerOrderProductChannel]: [
    'l3_customer',
    'order_type',
    'product',
    'channel',
  ],
};

export const DEFAULT_HIERARCHY_PRESET =
  RootCauseTreemapHierarchyPreset.OrderCustomerProductChannel;

export function getRootCauseTreemapHierarchy({
  columns,
  hierarchyPreset,
}: {
  columns?: QueryFormColumn[];
  hierarchyPreset?: RootCauseTreemapHierarchyPreset | string;
}) {
  if (hierarchyPreset === RootCauseTreemapHierarchyPreset.Custom) {
    return columns?.length
      ? columns
      : ROOT_CAUSE_TREEMAP_HIERARCHIES[DEFAULT_HIERARCHY_PRESET];
  }

  return (
    ROOT_CAUSE_TREEMAP_HIERARCHIES[
      hierarchyPreset as Exclude<
        RootCauseTreemapHierarchyPreset,
        RootCauseTreemapHierarchyPreset.Custom
      >
    ] ||
    columns ||
    ROOT_CAUSE_TREEMAP_HIERARCHIES[DEFAULT_HIERARCHY_PRESET]
  );
}

export type RootCauseTreemapFormData = QueryFormData & {
  columns: QueryFormColumn[];
  hierarchyPreset: RootCauseTreemapHierarchyPreset;
  metric?: QueryFormMetric;
  secondaryMetric?: QueryFormMetric;
  tooltipMetrics?: QueryFormMetric[];
  labelType: RootCauseTreemapLabelType;
  labelPosition: LabelPositionEnum;
  showLabels: boolean;
  showUpperLabels: boolean;
  numberFormat: string;
  performanceFormat: string;
  dateFormat: string;
  colorMin?: string | number | null;
  colorMax?: string | number | null;
  excludeNegativeContribution: boolean;
  removePerformanceOutliers: boolean;
  performanceAggregation: PerformanceAggregation;
  visibleMin: string | number;
  orderTypeValues?: DataRecordValue[];
  cohortValues?: DataRecordValue[];
  l3CustomerValues?: DataRecordValue[];
  productDistanceValues?: DataRecordValue[];
  productionPlantValues?: DataRecordValue[];
  productGroupIbpGroup2Values?: DataRecordValue[];
  distributionChannelValues?: DataRecordValue[];
  kosherNonKosherValues?: DataRecordValue[];
  organicNonOrganicValues?: DataRecordValue[];
  nonGmoIndicatorValues?: DataRecordValue[];
  lactoseFreeIndicatorValues?: DataRecordValue[];
  brandedPrivateLabelValues?: DataRecordValue[];
  dashboardId?: number;
  sliceId?: number;
};

export type RootCauseMetricMap = Record<string, number>;

export type RootCauseTreeNode = {
  name: DataRecordValue;
  formattedName: string;
  groupBy: string;
  records: DataRecordValue[];
  value: number;
  areaValue: number;
  performance: number;
  metrics: RootCauseMetricMap;
  rowCount: number;
  children?: RootCauseTreeNode[];
};

export interface RootCauseTreemapChartProps
  extends ChartProps<RootCauseTreemapFormData> {
  formData: RootCauseTreemapFormData;
  queriesData: ChartDataResponseResult[];
}

export const DEFAULT_FORM_DATA: Partial<RootCauseTreemapFormData> = {
  columns: ROOT_CAUSE_TREEMAP_HIERARCHIES[DEFAULT_HIERARCHY_PRESET],
  hierarchyPreset: DEFAULT_HIERARCHY_PRESET,
  labelType: RootCauseTreemapLabelType.RootCause,
  labelPosition: LabelPositionEnum.InsideTopLeft,
  numberFormat: 'SMART_NUMBER',
  performanceFormat: '.2%',
  showLabels: true,
  showUpperLabels: true,
  dateFormat: 'smart_date',
  colorMin: -0.15,
  colorMax: 0.15,
  excludeNegativeContribution: false,
  removePerformanceOutliers: false,
  performanceAggregation: PerformanceAggregation.WeightedAverage,
  visibleMin: 8,
  orderTypeValues: [],
  cohortValues: [],
  l3CustomerValues: [],
  productDistanceValues: [],
  productionPlantValues: [],
  productGroupIbpGroup2Values: [],
  distributionChannelValues: [],
  kosherNonKosherValues: [],
  organicNonOrganicValues: [],
  nonGmoIndicatorValues: [],
  lactoseFreeIndicatorValues: [],
  brandedPrivateLabelValues: [],
};

export type RootCauseTreemapCallbackDataParams = Omit<
  CallbackDataParams,
  'data'
> & {
  data?: RootCauseTreeNode & {
    custom?: RootCauseTreeNode & {
      path: string[];
      contributionShare: number;
      parentShare?: number;
      metricLabels: string[];
    };
  };
  treePathInfo?: TreePathInfo[];
};

export type RootCauseTreemapTransformedProps =
  BaseTransformedProps<RootCauseTreemapFormData> &
    ContextMenuTransformedProps &
    Omit<CrossFilterTransformedProps, 'labelMap'> & {
      labelMap: Record<string, DataRecordValue[]>;
    };
