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
import { useEffect, useState } from 'react';
import { SupersetClient } from '@superset-ui/core';

export type AudienceGroup = { id: string; name: string | null };

export type DashboardAudience = {
  state: string;
  groups: AudienceGroup[];
  foreignRoles: string[];
};

export type AudienceResult =
  | { status: 'loading' }
  | { status: 'unsupported' }
  | { status: 'error' }
  | { status: 'ready'; audience: DashboardAudience };

// 501 means this Superset isn't backed by PlaidCloud; any other failure is a
// PlaidCloud problem, which must not fall back to raw Superset roles.
export const useDashboardAudience = (dashboardId: number): AudienceResult => {
  const [result, setResult] = useState<AudienceResult>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    SupersetClient.get({
      endpoint: `/api/v1/dashboard/${dashboardId}/audience`,
    })
      .then(({ json }) => {
        if (!cancelled)
          setResult({
            status: 'ready',
            audience: {
              state: json.result.state,
              groups: json.result.groups,
              foreignRoles: json.result.foreign_roles,
            },
          });
      })
      .catch(async error => {
        const status = error?.status ?? error?.response?.status;
        if (!cancelled) {
          setResult({ status: status === 501 ? 'unsupported' : 'error' });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [dashboardId]);

  return result;
};
