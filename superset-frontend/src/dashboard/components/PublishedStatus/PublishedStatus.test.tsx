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
import { render, screen, userEvent } from 'spec/helpers/testing-library';
import PublishedStatus from '.';

const defaultProps = {
  dashboardId: 1,
  isPublished: false,
  savePublished: jest.fn(),
  userCanEdit: false,
  userCanSave: false,
};

test('renders with unpublished status and readonly permissions', async () => {
  const tooltip =
    /This dashboard is not published which means it will not show up in the list of dashboards/;
  render(<PublishedStatus {...defaultProps} />);
  expect(screen.getByText('Draft')).toBeInTheDocument();
  userEvent.hover(screen.getByText('Draft'));
  expect(await screen.findByText(tooltip)).toBeInTheDocument();
});

test('renders with unpublished status and write permissions', async () => {
  const tooltip =
    /This dashboard is not published, it will not show up in the list of dashboards/;
  const savePublished = jest.fn();
  render(
    <PublishedStatus
      {...defaultProps}
      userCanEdit
      userCanSave
      savePublished={savePublished}
    />,
  );
  expect(screen.getByText('Draft')).toBeInTheDocument();
  userEvent.hover(screen.getByText('Draft'));
  expect(await screen.findByText(tooltip)).toBeInTheDocument();
  expect(savePublished).not.toHaveBeenCalled();
  userEvent.click(screen.getByText('Draft'));
  expect(savePublished).toHaveBeenCalledTimes(1);
});

test('renders with published status and readonly permissions', () => {
  render(<PublishedStatus {...defaultProps} isPublished />);
  expect(screen.queryByText('Published')).not.toBeInTheDocument();
});

test('renders with published status and write permissions', async () => {
  const tooltip = /This dashboard is published. Click to make it a draft/;
  const savePublished = jest.fn();
  render(
    <PublishedStatus
      {...defaultProps}
      isPublished
      userCanEdit
      userCanSave
      savePublished={savePublished}
    />,
  );
  expect(screen.getByText('Published')).toBeInTheDocument();
  userEvent.hover(screen.getByText('Published'));
  expect(await screen.findByText(tooltip)).toBeInTheDocument();
  expect(savePublished).not.toHaveBeenCalled();
  userEvent.click(screen.getByText('Published'));
  expect(savePublished).toHaveBeenCalledTimes(1);
});

test('keeps the Draft badge and adds Manage in PlaidCloud for a sentinel-only dashboard', () => {
  render(
    <PublishedStatus
      {...defaultProps}
      dashboardId={7}
      userCanEdit
      userCanSave
      roles={[{ id: 3, name: 'plaid_dashboard_owners_only' }]}
    />,
  );
  expect(screen.getByText('Draft')).toBeInTheDocument();
  expect(
    screen.getByRole('link', { name: /Manage in PlaidCloud/ }),
  ).toHaveAttribute(
    'href',
    'http://localhost/#dashboard.audience~%7B%22dashboard_id%22%3A7%7D',
  );
});

test('keeps the Draft button when the dashboard has a group role too', () => {
  render(
    <PublishedStatus
      {...defaultProps}
      userCanEdit
      userCanSave
      roles={[
        { id: 3, name: 'plaid_dashboard_owners_only' },
        { id: 4, name: 'plaid_rls_a' },
      ]}
    />,
  );
  expect(screen.getByText('Draft')).toBeInTheDocument();
  expect(screen.queryByText('Manage in PlaidCloud')).not.toBeInTheDocument();
});
