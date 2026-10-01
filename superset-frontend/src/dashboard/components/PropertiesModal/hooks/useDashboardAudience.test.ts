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
import { renderHook } from '@testing-library/react-hooks';
import { SupersetClient } from '@superset-ui/core';
import { useDashboardAudience } from './useDashboardAudience';

const audience = { state: 'everyone', groups: [], foreignRoles: [] };
const wire = { state: 'everyone', groups: [], foreign_roles: [] };

test('ready with the audience from the plaid-backed endpoint', async () => {
  jest
    .spyOn(SupersetClient, 'get')
    .mockResolvedValue({ json: { result: wire } } as any);

  const { result, waitFor } = renderHook(() => useDashboardAudience(7));

  await waitFor(() =>
    expect(result.current).toEqual({ status: 'ready', audience }),
  );
  expect(SupersetClient.get).toHaveBeenCalledWith({
    endpoint: '/api/v1/dashboard/7/audience',
  });
});

test('501 is unsupported, any other failure is an error', async () => {
  const get = jest.spyOn(SupersetClient, 'get');

  get.mockRejectedValue({ status: 501 });
  const unsupported = renderHook(() => useDashboardAudience(7));
  await unsupported.waitFor(() =>
    expect(unsupported.result.current).toEqual({ status: 'unsupported' }),
  );

  get.mockRejectedValue({ status: 502 });
  const failed = renderHook(() => useDashboardAudience(7));
  await failed.waitFor(() =>
    expect(failed.result.current).toEqual({ status: 'error' }),
  );
});
