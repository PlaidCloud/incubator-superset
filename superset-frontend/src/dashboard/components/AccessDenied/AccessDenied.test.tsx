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
import { SupersetClient } from '@superset-ui/core';
import {
  render,
  screen,
  userEvent,
  waitFor,
} from 'spec/helpers/testing-library';
import AccessDenied from '.';

afterEach(() => {
  jest.restoreAllMocks();
});

const GENERIC = "This dashboard doesn't exist or you don't have access.";

const mockPost = (context: object = {}) =>
  jest.spyOn(SupersetClient, 'post').mockImplementation(({ endpoint }) =>
    Promise.resolve({
      json: endpoint?.endsWith('access_context')
        ? { result: context }
        : { status: 'sent' },
    } as never),
  );

const requestCalls = (post: jest.SpyInstance) =>
  post.mock.calls.filter(([{ endpoint }]) =>
    endpoint.endsWith('access_request'),
  );

test('asks for context on load but sends no request until the user clicks', async () => {
  const post = mockPost();

  render(<AccessDenied idOrSlug="7" />);

  expect(await screen.findByText(GENERIC)).toBeInTheDocument();
  expect(post).toHaveBeenCalledWith({
    endpoint: '/api/v1/dashboard/access_context',
    jsonPayload: { dashboard_id: 7 },
  });
  expect(requestCalls(post)).toHaveLength(0);
});

test('shows the title and owners when PlaidCloud returns them', async () => {
  mockPost({ title: 'Recon', owners: ['Paul', 'Chris'] });

  render(<AccessDenied idOrSlug="7" />);

  expect(
    await screen.findByText("You don't have access to Recon."),
  ).toBeInTheDocument();
  expect(screen.getByText('Owners: Paul, Chris')).toBeInTheDocument();
  expect(screen.queryByText(GENERIC)).not.toBeInTheDocument();
});

test('stays generic when the context call fails', async () => {
  jest.spyOn(SupersetClient, 'post').mockRejectedValue(new Error('down'));

  render(<AccessDenied idOrSlug="7" />);

  expect(await screen.findByText(GENERIC)).toBeInTheDocument();
});

test('links back to the dashboards list', () => {
  mockPost();

  render(<AccessDenied idOrSlug="7" />);

  expect(
    screen.getByRole('link', { name: 'Back to Dashboards' }),
  ).toHaveAttribute('href', '/dashboard/list/');
});

test('posts the id as sent and the note, then confirms', async () => {
  const post = mockPost();

  render(<AccessDenied idOrSlug="my-slug" />);
  userEvent.type(
    screen.getByPlaceholderText('Note to the owners (optional)'),
    '<b>please</b>',
  );
  userEvent.click(screen.getByRole('button', { name: 'Request access' }));

  expect(await screen.findByText('Your request was sent')).toBeInTheDocument();
  expect(requestCalls(post)).toEqual([
    [
      {
        endpoint: '/api/v1/dashboard/access_request',
        jsonPayload: { dashboard_id: 'my-slug', note: '<b>please</b>' },
      },
    ],
  ]);
});

test('shows an error and lets the user retry when the request fails', async () => {
  jest.spyOn(SupersetClient, 'post').mockRejectedValue(new Error('down'));

  render(<AccessDenied idOrSlug="7" />);
  userEvent.click(screen.getByRole('button', { name: 'Request access' }));

  expect(await screen.findByRole('alert')).toHaveTextContent(
    "Your request couldn't be sent. Please try again.",
  );
  await waitFor(() =>
    expect(
      screen.getByRole('button', { name: 'Request access' }),
    ).toBeEnabled(),
  );
});
