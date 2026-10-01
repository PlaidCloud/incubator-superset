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
import { plaidcloudAudienceUrl } from './plaidcloudUrl';

const expectedHash = '#dashboard.audience~%7B%22dashboard_id%22%3A7%7D';

function withOrigin(origin: string) {
  Object.defineProperty(window, 'location', {
    value: { origin },
    writable: true,
  });
}

test('strips the dashboards. prefix from the origin', () => {
  withOrigin('https://dashboards.acme.plaidcloud.io');
  expect(plaidcloudAudienceUrl(7)).toBe(
    `https://acme.plaidcloud.io/${expectedHash}`,
  );
});

test('keeps an origin without the dashboards. prefix', () => {
  withOrigin('https://acme.plaidcloud.io');
  expect(plaidcloudAudienceUrl(7)).toBe(
    `https://acme.plaidcloud.io/${expectedHash}`,
  );
});
