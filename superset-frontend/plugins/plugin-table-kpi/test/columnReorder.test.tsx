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

/**
 * Drag-and-drop column reordering had no coverage at all, which is what made
 * the nested-`<th>` fix (sc-25372) risky: the wrapper `<th>` carries the
 * handlers that reorder columns, the inner `<th>` carries its own, and a
 * regression in either would have been silent. These tests pin the behaviour
 * so the markup can be changed underneath them.
 */
import '@testing-library/jest-dom';
import { fireEvent, render } from '@testing-library/react';
import TableChart from '../src/TableChart';
import transformProps from '../src/transformProps';
import testData from './testData';
import { ProviderWrapper } from './testHelpers';

const columnOrder = () =>
  Array.from(
    document.querySelectorAll<HTMLTableCellElement>('th[data-column-name]'),
  ).map(th => th.dataset.columnName);

const renderChart = () =>
  render(
    ProviderWrapper({
      children: (
        <TableChart
          {...transformProps(testData.basic)}
          sticky={false}
          allowRearrangeColumns
        />
      ),
    }),
  );

/** A drag carries its state on the event; jsdom does not supply one. */
const drag = (from: Element, to: Element) => {
  const dataTransfer = { effectAllowed: '' };
  fireEvent.dragStart(from, { dataTransfer });
  fireEvent.drop(to, { dataTransfer });
};

test('dragging a header onto another one swaps their positions', () => {
  renderChart();
  const before = columnOrder();
  expect(before.length).toBeGreaterThan(1);

  const headers = document.querySelectorAll('th[data-column-name]');
  drag(headers[0], headers[1]);

  const after = columnOrder();
  expect(after[0]).toBe(before[1]);
  expect(after[1]).toBe(before[0]);
});

test('the columns not involved in the drag keep their order', () => {
  renderChart();
  const before = columnOrder();
  // Only meaningful with a column left over on the right-hand side.
  expect(before.length).toBeGreaterThan(2);

  const headers = document.querySelectorAll('th[data-column-name]');
  drag(headers[0], headers[1]);

  expect(columnOrder().slice(2)).toEqual(before.slice(2));
});

test('dropping a header onto itself leaves the order untouched', () => {
  renderChart();
  const before = columnOrder();

  const headers = document.querySelectorAll('th[data-column-name]');
  drag(headers[0], headers[0]);

  expect(columnOrder()).toEqual(before);
});
