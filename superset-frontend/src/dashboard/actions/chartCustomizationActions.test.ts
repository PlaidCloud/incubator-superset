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
import { combineReducers, createStore, applyMiddleware, compose } from 'redux';
import thunk from 'redux-thunk';
import fetchMock from 'fetch-mock';
import { ChartCustomization } from '@superset-ui/core';
import mockState from 'spec/fixtures/mockState';
import reducerIndex from 'spec/helpers/reducerIndex';
import { saveChartCustomization } from './chartCustomizationActions';

const NATIVE_FILTER_ID = 'NATIVE_FILTER-abc123';
const CUSTOMIZATION_ID = 'CHART_CUSTOMIZATION-def456';
const DELETED_CUSTOMIZATION_ID = 'CHART_CUSTOMIZATION-ghi789';

const nativeFilter = {
  id: NATIVE_FILTER_ID,
  name: 'Region',
  filterType: 'filter_select',
  chartsInScope: [10],
  targets: [{}],
  cascadeParentIds: [],
};

const customization = {
  id: CUSTOMIZATION_ID,
  type: 'CHART_CUSTOMIZATION',
  name: 'Table Column Selection',
  filterType: 'chart_customization_dynamic_groupby',
  chartsInScope: [10],
  tabsInScope: [],
  targets: [{ datasetId: 1 }],
  cascadeParentIds: [],
} as unknown as ChartCustomization;

const deletedCustomization = {
  ...customization,
  id: DELETED_CUSTOMIZATION_ID,
} as unknown as ChartCustomization;

test('saveChartCustomization keeps native filters in the nativeFilters map', async () => {
  fetchMock.put('glob:*/api/v1/dashboard/*/chart_customizations', {
    result: [customization],
  });

  const store = createStore(
    combineReducers(reducerIndex),
    {
      ...mockState,
      nativeFilters: {
        filters: {
          [NATIVE_FILTER_ID]: nativeFilter,
          [CUSTOMIZATION_ID]: customization,
          [DELETED_CUSTOMIZATION_ID]: deletedCustomization,
        },
      },
    },
    compose(applyMiddleware(thunk)),
  );

  await store.dispatch(
    saveChartCustomization([customization], [DELETED_CUSTOMIZATION_ID]) as any,
  );

  const { filters } = (store.getState() as any).nativeFilters;
  // the customization save must not wipe native filters from the map —
  // the filter bar still renders them, and the focus/hover highlight path
  // looks them up by id (sc-25710)
  expect(filters[NATIVE_FILTER_ID]).toMatchObject({ id: NATIVE_FILTER_ID });
  expect(filters[CUSTOMIZATION_ID]).toMatchObject({ id: CUSTOMIZATION_ID });
  expect(filters[DELETED_CUSTOMIZATION_ID]).toBeUndefined();

  fetchMock.removeRoutes();
});
