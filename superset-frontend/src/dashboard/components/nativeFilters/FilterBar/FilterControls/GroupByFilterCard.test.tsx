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
import rison from 'rison';
import {
  createStore,
  render,
  screen,
  userEvent,
  waitFor,
} from 'spec/helpers/testing-library';
import reducerIndex from 'spec/helpers/reducerIndex';
import { ChartCustomization, ChartCustomizationType } from '@superset-ui/core';
import { updateDataMask } from 'src/dataMask/actions';
import { cachedSupersetGet } from 'src/utils/cachedSupersetGet';
import GroupByFilterCard from './GroupByFilterCard';

jest.mock('src/utils/cachedSupersetGet');

const mockCachedSupersetGet = cachedSupersetGet as jest.MockedFunction<
  typeof cachedSupersetGet
>;

const columns = [
  { column_name: 'region', filterable: true },
  { column_name: 'country', filterable: true },
  { column_name: 'ssn', filterable: false },
];

const card = (controlValues: ChartCustomization['controlValues']) => (
  <GroupByFilterCard
    customizationItem={{
      id: 'CHART_CUSTOMIZATION-1',
      type: ChartCustomizationType.ChartCustomization,
      name: 'Group by',
      filterType: 'chart_customization_dynamic_groupby',
      targets: [{ datasetId: 1 }],
      scope: { rootPath: ['ROOT_ID'], excluded: [] },
      defaultDataMask: {},
      controlValues,
    }}
  />
);

// Select sorts options by label.
const optionTitles = () =>
  Array.from(document.querySelectorAll('.ant-select-item-option'), option =>
    option.getAttribute('title'),
  );

const renderCard = async (
  controlValues: ChartCustomization['controlValues'],
) => {
  mockCachedSupersetGet.mockResolvedValue({
    json: { result: { table_name: 'tbl', columns } },
  } as any);
  // One store across rerenders, so only the allowlist changes between them.
  const store = createStore(
    { dataMask: {}, nativeFilters: { filters: {} } },
    reducerIndex,
  );
  const { rerender } = render(card(controlValues), { store });
  await waitFor(() => expect(mockCachedSupersetGet).toHaveBeenCalled());
  await userEvent.click(screen.getByRole('combobox'));
  await waitFor(() => expect(optionTitles().length).toBeGreaterThan(0));
  return { rerender, store };
};

afterEach(() => {
  mockCachedSupersetGet.mockReset();
});

test('lists every filterable column when no allowlist is set', async () => {
  await renderCard({});
  expect(optionTitles()).toEqual(['country', 'region']);
});

test('lists only allowlisted filterable columns', async () => {
  await renderCard({ availableColumns: ['country', 'ssn'] });
  expect(optionTitles()).toEqual(['country']);
});

test('lists every filterable column when the allowlist is empty', async () => {
  await renderCard({ availableColumns: [] });
  expect(optionTitles()).toEqual(['country', 'region']);
});

test('requests only the dataset fields the card reads', async () => {
  await renderCard({});
  expect(mockCachedSupersetGet).toHaveBeenCalledWith({
    endpoint: `/api/v1/dataset/1?q=${rison.encode({
      columns: [
        'table_name',
        'columns.column_name',
        'columns.verbose_name',
        'columns.filterable',
      ],
    })}`,
  });
});

test('re-applies the allowlist when it changes', async () => {
  const { rerender } = await renderCard({});
  rerender(card({ availableColumns: ['region'] }));
  await waitFor(() => expect(optionTitles()).toEqual(['region']));
});

test('does not refetch columns when another filter changes', async () => {
  const { store } = await renderCard({});
  store.dispatch(
    updateDataMask('NATIVE_FILTER-1', { filterState: { value: ['x'] } }),
  );
  await new Promise(resolve => setTimeout(resolve, 50));
  expect(mockCachedSupersetGet).toHaveBeenCalledTimes(1);
});
