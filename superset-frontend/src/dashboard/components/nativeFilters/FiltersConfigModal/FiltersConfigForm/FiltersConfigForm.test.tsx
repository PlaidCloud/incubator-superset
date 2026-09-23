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
import { ChartCustomizationType, Preset } from '@superset-ui/core';
import { Form, type FormInstance } from '@superset-ui/core/components';
import { Provider } from 'react-redux';
import { mockStoreWithChartsInTabsAndRoot } from 'spec/fixtures/mockStore';
import {
  render,
  screen,
  userEvent,
  waitFor,
} from 'spec/helpers/testing-library';
import { ChartCustomizationDynamicGroupBy } from 'src/chartCustomizations/components';
import { ChartCustomizationPlugins } from 'src/constants';
import { cachedSupersetGet } from 'src/utils/cachedSupersetGet';
import FiltersConfigForm from './FiltersConfigForm';
import { createMockedProps } from './FilterScope/__tests__/utils';

jest.mock('src/utils/cachedSupersetGet');

const { filterId } = createMockedProps();
let formRef: FormInstance;

const CustomizationForm = () => {
  const [form] = Form.useForm();
  formRef = form;
  return (
    <Provider store={mockStoreWithChartsInTabsAndRoot}>
      <Form form={form}>
        <FiltersConfigForm
          form={form}
          {...createMockedProps()}
          itemType="chartCustomization"
          customizationToEdit={{
            id: filterId,
            type: ChartCustomizationType.ChartCustomization,
            name: 'Group by',
            filterType: ChartCustomizationPlugins.DynamicGroupBy,
            targets: [{ datasetId: 1 }],
            scope: { rootPath: ['ROOT_ID'], excluded: [] },
            defaultDataMask: {},
            controlValues: {},
          }}
        />
      </Form>
    </Provider>
  );
};

beforeAll(() => {
  new Preset({
    name: 'customizations',
    plugins: [
      new ChartCustomizationDynamicGroupBy().configure({
        key: ChartCustomizationPlugins.DynamicGroupBy,
      }),
    ],
  }).register();
});

test('offers filterable columns as available columns and saves the pick', async () => {
  (cachedSupersetGet as jest.Mock).mockResolvedValue({
    json: {
      result: {
        id: 1,
        table_name: 'tbl',
        datasource_type: 'table',
        database: { id: 1, database_name: 'db' },
        metrics: [],
        columns: [
          { column_name: 'region', filterable: true },
          { column_name: 'country', filterable: true },
          { column_name: 'ssn', filterable: false },
        ],
      },
    },
  });
  render(<CustomizationForm />);

  await userEvent.click(
    await screen.findByRole('combobox', { name: 'Available columns' }),
  );
  // Select sorts options by label.
  await waitFor(() =>
    expect(
      Array.from(document.querySelectorAll('.ant-select-item-option'), o =>
        o.getAttribute('title'),
      ),
    ).toEqual(['country', 'region']),
  );
  await userEvent.click(screen.getByTitle('region'));

  expect(
    formRef.getFieldValue(['filters', filterId, 'controlValues']),
  ).toMatchObject({ availableColumns: ['region'] });
});
